use blind_rsa_signatures::{BlindingResult, Options, PublicKey as RsaPublicKey};

use crate::shared::{Ballot, BallotToken, VoteID, Error, BallotSig};

impl Ballot {
    pub fn from_token(
        token: BallotToken,
        opt: String,
        blinding_result: &BlindingResult,
        claim_token: &[u8],
        options: &Options,
        pk: &RsaPublicKey,
        vote_id: &VoteID,
    ) -> Result<Self, Error> {
        let sig = pk.finalize(
            &token.blinded_sig.into(),
            &blinding_result.secret,
            blinding_result.msg_randomizer,
            &claim_token,
            &options,
        )?;

        Ok(Ballot {
            vote_id: vote_id.clone(),
            opt,
            sig: BallotSig::Blind(sig.into()),
        })
    }
}