use blind_rsa_signatures::{
    reexports::rsa::{self, pkcs8::DecodePublicKey},
    Options, PublicKey as RsaPublicKey,
};
use concilia_shared::{Ballot, BallotID, BallotToken, Error, StringConversion, Vote, VoteID};
use kt2::{PublicKey, SIGN_BYTES};

pub struct Client {
    client: reqwest::Client,
    host: String,
}

impl Client {
    pub fn new(host: impl AsRef<str>) -> Self {
        Self {
            client: reqwest::Client::new(),
            host: host.as_ref().to_string(),
        }
    }
    
    pub async fn submit_ballot(&self, vote: &Vote, opt: String) -> Result<BallotID, Error> {
        // 2. VOTER authenticates themselves to receive a blinded signature signed by vote's secret key
        // This would usually include some sort of ID check. Personal info is okay-ish to hand over
        // because the server can't link blind_msg to the submitted ballot
    
        // get server kt2 public key
        let res = self.client
            .get(format!("{}/kt2_public", self.host))
            .send()
            .await?;
        let pk_bytes = bs58::decode(res.json::<String>().await?)
            .into_vec()
            .map_err(|_| Error::SerializationError)?;
        let pk = PublicKey::from_bytes(&pk_bytes);
    
        let vote_id = VoteID::new(&vote);
        let options = Options::default();
        let claim_token: [u8; 32] = rand::random();
        // let claim_token: [u8; 32] = *b"testtesttesttesttesttesttesttest";
        let vote_pk = RsaPublicKey::from(rsa::RsaPublicKey::from_public_key_der(&vote.pk).unwrap());
        let blinding_result = vote_pk.blind(&mut rand::thread_rng(), claim_token, true, &options)?;
        let blind_msg = blinding_result.blind_msg.clone();
    
        // post (vote_id, blind_msg) -> SERVER
        let blind_msg = blind_msg.0;
        let body = (vote_id, blind_msg);
        let res = self.client
            .post(format!("{}/verify_eligibility", self.host))
            .json(&body)
            .send()
            .await?;
        let token = BallotToken::from_string(res.json().await?).ok_or(Error::SerializationError)?;
    
        // 3. Voter unblinds the token into a signature
        // VOTER
        let ballot = Ballot::from_token(
            token,
            opt,
            &blinding_result,
            &claim_token,
            &options,
            &vote_pk,
        )?;
        // post (ballot, msg_randomizer, claim_token) -> SERVER
        let msg_randomizer = blinding_result.msg_randomizer.map(|m| m.0);
        let body = (vote_id, ballot, msg_randomizer, claim_token);
        let res = self.client
            .post(format!("{}/submit_ballot", self.host))
            .json(&body)
            .send()
            .await?;
        let (ballot_id, kt2_sig) = res.json::<(String, String)>().await?;
        let ballot_id = BallotID::from_string(ballot_id).ok_or(Error::SerializationError)?;
        let kt2_sig = {
            let vec = bs58::decode(&kt2_sig).into_vec().unwrap();
            let mut bytes = [0u8; SIGN_BYTES];
            if vec.len() != bytes.len() {
                return Err(Error::BadBallotReceiptSignature);
            }
            bytes.copy_from_slice(&vec);
            kt2::Signature(bytes)
        };
        if !pk.verify(&ballot_id.0, &kt2_sig) {
            return Err(Error::BadBallotReceiptSignature);
        }
    
        Ok(ballot_id)
    }
    
    pub async fn create_vote(
        &self, title: impl AsRef<str>,
        desc: impl AsRef<str>,
        options: impl AsRef<[&str]>,
    ) -> Result<VoteID, Error> {
        let res = self.client
            .post(format!("{}/create_vote", self.host))
            .json(&(
                title.as_ref().to_string(),
                desc.as_ref().to_string(),
                options
                    .as_ref()
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            ))
            .send()
            .await?;
        let vote_id = VoteID::from_string(res.json().await?).ok_or(Error::SerializationError)?;
        Ok(vote_id)
    }
    
    pub async fn get_vote(&self, vote_id: &VoteID) -> Result<Vote, Error> {
        let res = self.client
            .get(&format!("{}/vote/{}", self.host, vote_id))
            .send()
            .await?;
        Ok(res.json().await?)
    }
}
