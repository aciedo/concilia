//! Approximate Membership Query Filter ([AMQ-Filter](https://en.wikipedia.org/wiki/Approximate_Membership_Query_Filter))
//! based on the [Rank Select Quotient Filter (RSQF)](https://dl.acm.org/doi/pdf/10.1145/3035918.3035963). It uses xxhash3 as the hash function.
//!
//! ### Filter size
//!
//! For a given capacity and error probability the RSQF may require significantly less space than the equivalent bloom filter or other AMQ-Filters.
//!
//! | Bits per item | Error probability when full |
//! |--------|----------|
//! | 3.125  | 0.362    |
//! | 4.125  | 0.201    |
//! | 5.125  | 0.106    |
//! | 6.125  | 0.0547   |
//! | 7.125  | 0.0277   |
//! | 8.125  | 0.014    |
//! | 9.125  | 0.00701  |
//! | 10.125 | 0.00351  |
//! | 11.125 | 0.00176  |
//! | 12.125 | 0.000879 |
//! | 13.125 | 0.000439 |
//! | 14.125 | 0.00022  |
//! | 15.125 | 0.00011  |
//! | 16.125 | 5.49e-05 |
//! | 17.125 | 2.75e-05 |
//! | 18.125 | 1.37e-05 |
//! | 19.125 | 6.87e-06 |
//! | 20.125 | 3.43e-06 |
//! | 21.125 | 1.72e-06 |
//! | 22.125 | 8.58e-07 |
//! | 23.125 | 4.29e-07 |
//! | 24.125 | 2.15e-07 |
//! | 25.125 | 1.07e-07 |
//! | 26.125 | 5.36e-08 |
//! | 27.125 | 2.68e-08 |
//! | 28.125 | 1.34e-08 |
//! | 29.125 | 6.71e-09 |
//! | 30.125 | 3.35e-09 |
//! | 31.125 | 1.68e-09 |
//! | 32.125 | 8.38e-10 |

use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    num::{NonZeroU64, NonZeroU8},
    ops::{RangeBounds, RangeFrom},
};

use concilia_shared::Error;
use rkyv::{from_bytes, to_bytes, Archive, Deserialize, Serialize};
use sled::Db;
use tokio::sync::{RwLock, RwLockWriteGuard, RwLockReadGuard};
use tracing::{debug, info};

use crate::db::NEEDS_FLUSH;

/// Wrapper over a hasher that provides stable output across platforms
/// Based on https://github.com/rust-lang/rust/blob/c0955a34bcb17f0b31d7b86522a520ebe7fa93ac/src/librustc_data_structures/stable_hasher.rs#L78-L166
///
/// To that end we always convert integers to little-endian format before
/// hashing and the architecture dependent `isize` and `usize` types are
/// extended to 64 bits if needed.
pub struct StableHasher {
    /// Using xxh3-64 with default seed/secret as the portable hasher.
    state: xxhash_rust::xxh3::Xxh3,
}

impl StableHasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: xxhash_rust::xxh3::Xxh3::new(),
        }
    }
}

impl Hasher for StableHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.state.finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.state.write(bytes);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.state.write_u8(i);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.state.write_u16(i.to_le());
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.state.write_u32(i.to_le());
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.state.write_u64(i.to_le());
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.state.write_u128(i.to_le());
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        // Always treat usize as u64 so we get the same results on 32 and 64 bit
        // platforms. This is important for symbol hashes when cross compiling,
        // for example.
        self.state.write_u64((i as u64).to_le());
    }

    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.state.write_i8(i);
    }

    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.state.write_i16(i.to_le());
    }

    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.state.write_i32(i.to_le());
    }

    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.state.write_i64(i.to_le());
    }

    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.state.write_i128(i.to_le());
    }

    #[inline]
    fn write_isize(&mut self, i: isize) {
        // Always treat isize as i64 so we get the same results on 32 and 64 bit
        // platforms. This is important for symbol hashes when cross compiling,
        // for example.
        self.state.write_i64((i as i64).to_le());
    }
}

struct FilterShard {
    filters: Vec<Filter>,
    next_writable_filter: usize,
    length: u64,
    capacity: u64,
    target_fp_rate: f64,
}

impl FilterShard {
    fn new(capacity: u64, target_fp_rate: f64) -> Self {
        Self {
            filters: vec![],
            next_writable_filter: 0,
            length: 0,
            capacity,
            target_fp_rate,
        }
    }

    pub fn contains(&self, hash: u64) -> bool {
        self.filters.iter().any(|f| f.do_contains(hash))
    }

    pub fn insert(&mut self, hash: u64) -> Option<(usize, &Filter)> {
        if self.filters.len() == 0 {
            self.filters
                .push(Filter::new(self.capacity, self.target_fp_rate));
        }

        // try insert into next writable filter
        if match self.filters[self.next_writable_filter].do_insert(false, hash) {
            Ok(added) => added,
            // this filter is full, create a new one
            Err(_) => {
                self.next_writable_filter += 1;
                self.filters
                    .push(Filter::new(self.capacity, self.target_fp_rate));
                self.filters[self.next_writable_filter]
                    .do_insert(false, hash)
                    .unwrap()
            }
        } {
            self.length += 1;
            Some((
                self.next_writable_filter,
                &self.filters[self.next_writable_filter],
            ))
        } else {
            None
        }
    }

    pub fn len(&self) -> u64 {
        self.length
    }
    
    fn to_partial(&self) -> PartialFilterShard {
        PartialFilterShard {
            next_writable_filter: self.next_writable_filter,
            total_filters: self.filters.len(),
            length: self.length,
            capacity: self.capacity,
            target_fp_rate: self.target_fp_rate,
        }
    }
}

#[derive(Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
struct PartialFilterShard {
    next_writable_filter: usize,
    total_filters: usize,
    length: u64,
    capacity: u64,
    target_fp_rate: f64,
}

impl PartialFilterShard {
    fn save_to_db(&self, db: &Db, shard_id: usize) -> Result<(), Error> {
        debug!("Saving partial filter shard {}", shard_id);
        let value = to_bytes::<_, 1024>(self)
            .map_err(|_| Error::SerializationError)?;
        let key = [
            b"partial_filter_shard_",
            shard_id.to_be_bytes().as_ref(),
        ].concat();
        db.insert(key, value.as_ref())?;
        Ok(())
    }
}

/// ShardedFilter is a wrapper around Filter that handles automatic growth, partitioning
/// of and per shard async locking to increase vote throughput.
///
/// items are hashed to u64 (as hex) 0000000000000000
/// they are partioned on the last u8 ->           ||
/// the sharded filter hashes the provided item then uses the suffix
/// to determine which shard should be used. this distributes load
/// across the shards which allows for much greater throughput on
/// the filter for both reads and writes. each shard resizes itself
/// as needed to accomodate the number of items it is expected to.
pub struct ShardedFilter {
    shards: Vec<RwLock<FilterShard>>,
    capacity_per_shard: u64,
    target_fp_rate: f64,
}

pub struct WritableShardLock<'a> {
    shard: RwLockWriteGuard<'a, FilterShard>,
    shard_id: usize,
}

impl WritableShardLock<'_> {
    pub fn insert(&mut self, hash: u64, db: &Db) -> Result<bool, Error> {
        if let Some((filter_id, filter)) = self.shard.insert(hash) {
            filter.save_to_db(db, self.shard_id, filter_id)?;
            self.shard.to_partial().save_to_db(db, self.shard_id)?;
            NEEDS_FLUSH.clone().notify_waiters();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn contains(&self, hash: u64) -> bool {
        self.shard.contains(hash)
    }
}

pub struct ReadableShardLock<'a> {
    shard: RwLockReadGuard<'a, FilterShard>,
}

impl ReadableShardLock<'_> {
    pub fn contains(&self, hash: u64) -> bool {
        self.shard.contains(hash)
    }
}

impl ShardedFilter {
    pub fn new(capacity_per_shard: u64, target_fp_rate: f64) -> Self {
        Self {
            shards: {
                let mut shards = Vec::with_capacity(256);
                for _ in 0..256 {
                    shards.push(RwLock::new(FilterShard::new(
                        capacity_per_shard,
                        target_fp_rate,
                    )));
                }
                shards
            },
            capacity_per_shard,
            target_fp_rate,
        }
    }

    pub async fn len(&self) -> u64 {
        let mut len = 0;
        for shard in self.shards.iter() {
            len += shard.read().await.len();
        }
        len
    }
    
    pub async fn lock_shard<'a>(&'a self, hash: &u64) -> ReadableShardLock<'a> {
        let shard_id = *hash as usize % 256;
        let shard = self.shards[shard_id].read().await;
        ReadableShardLock { shard }
    }
    
    pub async fn lock_shard_mut<'a>(&'a self, hash: &u64) -> WritableShardLock<'a> {
        let shard_id = *hash as usize % 256;
        let shard = self.shards[shard_id].write().await;
        WritableShardLock { shard, shard_id }
    }
    
    pub async fn insert<T: Hash>(&self, item: &T, db: &Db) -> Result<bool, Error> {
        let hash = Filter::hash(item);
        self.lock_shard_mut(&hash).await.insert(hash, db)
    }
    
    pub async fn contains<T: Hash>(&self, item: &T) -> bool {
        let hash = Filter::hash(item);
        self.lock_shard(&hash).await.contains(hash)
    }
    
    pub async fn save_to_db(&self, db: &Db) -> Result<(), Error> {
        // save partial self to db
        self.to_partial().save_to_db(db)?;
        // save each shard
        for (shard_id, shard) in self.shards.iter().enumerate() {
            let shard = shard.read().await;
            shard.to_partial().save_to_db(db, shard_id)?;
            for (filter_id, filter) in shard.filters.iter().enumerate() {
                filter.save_to_db(db, shard_id, filter_id)?
            }
        }
        NEEDS_FLUSH.clone().notify_waiters();
        Ok(())
    }

    pub fn recover_from_db(db: &Db) -> Result<Self, Error> {
        // load partial sharded filter from db
        debug!("loading partial sharded filter");
        let partial_sharded_filter: PartialShardedFilter = from_bytes(
            db.get(b"partial_sharded_filter")?
                .expect("no partial sharded filter found in db")
                .as_ref(),
        )
        .map_err(|_| Error::SerializationError)?;

        let mut total_filters = 0;
        let mut total_capacity = 0;
        let mut total_items = 0;
        // retrieve individual partial filter shards
        let shards = (0..256usize)
            .map(|shard_id| {
                debug!("loading partial filter shard {}", shard_id);
                let key = [b"partial_filter_shard_", shard_id.to_be_bytes().as_ref()].concat();
                let partial_filter_shard: PartialFilterShard = from_bytes(
                    db.get(key)?
                        .expect(&format!(
                            "partial filter shard {} not found in db",
                            shard_id
                        ))
                        .as_ref(),
                )
                .map_err(|_| Error::SerializationError)?;
                
                let mut filters = Vec::with_capacity(partial_filter_shard.total_filters);
                for filter_id in 0..partial_filter_shard.total_filters {
                    debug!("loading filter {} for shard {}", filter_id, shard_id);
                    let key = [
                        b"filter_",
                        shard_id.to_be_bytes().as_ref(),
                        filter_id.to_be_bytes().as_ref(),
                    ]
                    .concat();
                    let value = db.get(key)?.expect(&format!(
                        "filter {} not found in db for shard {}",
                        filter_id, shard_id
                    ));
                    filters.push(from_bytes(value.as_ref())
                        .map_err(|_| Error::SerializationError)?);
                    total_filters += 1;
                }
                let shard = FilterShard {
                    filters,
                    length: partial_filter_shard.length,
                    capacity: partial_filter_shard.capacity,
                    target_fp_rate: partial_sharded_filter.target_fp_rate,
                    next_writable_filter: partial_filter_shard.next_writable_filter,
                };
                
                total_capacity += shard.capacity;
                total_items += shard.len();
                Ok(RwLock::new(shard))
            })
            .collect::<Result<Vec<RwLock<FilterShard>>, Error>>()?;
        
        if shards.len() != 256 {
            panic!("shards were missing from db")
        }
        
        info!("Loaded {} filter shards with {} filters, {} items and {} active capacity", shards.len(), total_filters, total_items, total_capacity);
        
        // return sharded filter
        Ok(Self {
            shards,
            capacity_per_shard: partial_sharded_filter.capacity_per_shard,
            target_fp_rate: partial_sharded_filter.target_fp_rate,
        })
    }

    pub fn to_partial(&self) -> PartialShardedFilter {
        PartialShardedFilter {
            capacity_per_shard: self.capacity_per_shard,
            target_fp_rate: self.target_fp_rate,
        }
    }
}

#[derive(Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct PartialShardedFilter {
    capacity_per_shard: u64,
    target_fp_rate: f64,
}

impl PartialShardedFilter {
    pub fn save_to_db(&self, db: &Db) -> Result<(), Error> {
        debug!("Saving partial sharded filter");
        let value = to_bytes::<_, 1024>(self).map_err(|_| Error::SerializationError)?;
        db.insert(b"partial_sharded_filter", value.as_ref())?;
        Ok(())
    }
}

/// Approximate Membership Query Filter (AMQ-Filter) based on the Rank Select Quotient Filter (RSQF).
#[derive(Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct Filter {
    buffer: Vec<u8>,
    len: u64,
    qbits: NonZeroU8,
    rbits: NonZeroU8,
}

#[derive(Debug)]
pub enum QError {
    CapacityExceeded,
}

impl std::fmt::Display for QError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for QError {}

#[derive(Debug)]
struct Block {
    offset: u64,
    occupieds: u64,
    runends: u64,
}

trait BitExt {
    fn is_bit_set(&self, i: usize) -> bool;
    fn set_bit(&mut self, i: usize);
    fn clear_bit(&mut self, i: usize);
    fn shift_right(&self, bits: usize, b: &Self, b_start: usize, b_end: usize) -> Self;
    fn shift_left(&self, bits: usize, b: &Self, b_start: usize, b_end: usize) -> Self;
    /// Number of set bits (1s) in the range
    fn popcnt(&self, range: impl RangeBounds<u64>) -> u64;
    /// Index of nth set bits in the range
    fn select(&self, range: RangeFrom<u64>, n: u64) -> Option<u64>;

    #[inline]
    fn update_bit(&mut self, i: usize, value: bool) {
        if value {
            self.set_bit(i)
        } else {
            self.clear_bit(i)
        }
    }
}

impl BitExt for u64 {
    #[inline]
    fn is_bit_set(&self, i: usize) -> bool {
        (*self & (1 << i)) != 0
    }

    #[inline]
    fn set_bit(&mut self, i: usize) {
        *self |= 1 << i
    }

    #[inline]
    fn clear_bit(&mut self, i: usize) {
        *self &= !(1 << i)
    }

    #[inline]
    fn shift_right(&self, bits: usize, b: &Self, b_start: usize, b_end: usize) -> Self {
        let bitmask = |n| !u64::MAX.checked_shl(n).unwrap_or(0);
        let a_component = *self >> (64 - bits); // select the highest `bits` from A to become lowest
        let b_shifted_mask = bitmask((b_end - b_start) as u32) << b_start;
        let b_shifted = ((b_shifted_mask & b) << bits) & b_shifted_mask;
        let b_mask = !b_shifted_mask;

        a_component | b_shifted | (b & b_mask)
    }

    #[inline]
    fn shift_left(&self, bits: usize, b: &Self, b_start: usize, b_end: usize) -> Self {
        let bitmask = |n| !u64::MAX.checked_shl(n).unwrap_or(0);
        let a_component = *self << (64 - bits); // select the lowest `bits` from A to become highest
        let b_shifted_mask = bitmask((b_end - b_start) as u32) << b_start;
        let b_shifted = ((b_shifted_mask & b) >> bits) & b_shifted_mask;
        let b_mask = !b_shifted_mask;

        a_component | b_shifted | (b & b_mask)
    }

    #[inline]
    fn popcnt(&self, range: impl RangeBounds<u64>) -> u64 {
        let mut v = match range.start_bound() {
            std::ops::Bound::Included(&i) => *self >> i << i,
            std::ops::Bound::Excluded(&i) => *self >> (i + 1) << (i + 1),
            _ => *self,
        };
        v = match range.end_bound() {
            std::ops::Bound::Included(&i) if i < 63 => v & ((2 << i) - 1),
            std::ops::Bound::Excluded(&i) if i <= 63 => v & ((1 << i) - 1),
            _ => v,
        };

        #[cfg(target_arch = "x86_64")]
        let result = unsafe {
            // Using intrinsics introduce a function call, and the resulting code
            // ends up slower than the inline assembly below.
            // Any calls to is_x86_feature_detected also significantly affect performance.
            // Given this is available on all x64 cpus starting 2008 we assume it's present
            // (unless legacy_x86_64_support is set) and panic elsewhere otherwise.
            let popcnt;
            std::arch::asm!(
                "popcnt {popcnt}, {v}",
                v = in(reg) v,
                popcnt = out(reg) popcnt,
                options(pure, nomem, nostack)
            );
            popcnt
        };
        #[cfg(not(target_arch = "x86_64"))]
        let result = v.count_ones() as u64;

        result
    }

    #[inline]
    fn select(&self, range: RangeFrom<u64>, n: u64) -> Option<u64> {
        debug_assert!(range.start < 64);
        let v = *self >> range.start << range.start;

        #[cfg_attr(target_arch = "x86_64", cold)]
        #[cfg_attr(not(target_arch = "x86_64"), inline)]
        fn fallback(mut v: u64, n: u64) -> Option<u64> {
            for _ in 0..n / 8 {
                for _ in 0..8 {
                    v &= v.wrapping_sub(1); // remove the least significant bit
                }
            }
            for _ in 0..n % 8 {
                v &= v.wrapping_sub(1); // remove the least significant bit
            }

            if v == 0 {
                None
            } else {
                Some(v.trailing_zeros() as u64)
            }
        }

        #[cfg(target_arch = "x86_64")]
        let result = {
            // TODO: AMD CPUs up to Zen2 have slow BMI implementations
            if std::is_x86_feature_detected!("bmi2") {
                // This is the equivalent intrinsics version of the inline assembly below.
                // #[target_feature(enable = "bmi1")]
                // #[target_feature(enable = "bmi2")]
                // #[inline]
                // unsafe fn select_bmi2(x: u64, k: u64) -> Option<u64> {
                //     use std::arch::x86_64::{_pdep_u64, _tzcnt_u64};
                //     let result = _tzcnt_u64(_pdep_u64(1 << k, x));
                //     if result != 64 {
                //         Some(result)
                //     } else {
                //         None
                //     }
                // }
                // unsafe { select_bmi2(v, n) }

                let result: u64;
                unsafe {
                    std::arch::asm!(
                        "mov     {tmp}, 1",
                        "shlx    {tmp}, {tmp}, {n}",
                        "pdep    {tmp}, {tmp}, {v}",
                        "tzcnt   {tmp}, {tmp}",
                        n = in(reg) n,
                        v = in(reg) v,
                        tmp = out(reg) result,
                        options(pure, nomem, nostack)
                    );
                }
                if result != 64 {
                    Some(result)
                } else {
                    None
                }
            } else {
                fallback(v, n)
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let result = fallback(v, n);

        result
    }
}

trait CastNonZeroU8 {
    fn u64(&self) -> u64;
    fn usize(&self) -> usize;
}

impl CastNonZeroU8 for NonZeroU8 {
    #[inline]
    fn u64(&self) -> u64 {
        self.get() as u64
    }

    #[inline]
    fn usize(&self) -> usize {
        self.get() as usize
    }
}

impl Filter {
    /// Creates a new filter that can hold at least `capacity` items
    /// and with a desired error rate of `fp_rate` (clamped to (0, 0.5]).
    ///
    /// # Panics
    /// Panics if memory cannot be allocated or if capacity >= u64::MAX / 20.
    /// Panics if the capacity and false positive rate isn't achievable using 64 bit hashes.
    pub fn new(capacity: u64, fp_rate: f64) -> Self {
        let fp_rate = fp_rate.clamp(f64::MIN_POSITIVE, 0.5);
        // Calculate necessary slots to achieve capacity with up to 95% occupancy
        // 19/20 == 0.95
        let qbits = (capacity * 20 / 19)
            .next_power_of_two()
            .max(64)
            .trailing_zeros() as u8;
        let rbits = (-fp_rate.log2()).round().max(1.0) as u8;
        Self::with_qr(qbits.try_into().unwrap(), rbits.try_into().unwrap())
    }

    fn with_qr(qbits: NonZeroU8, rbits: NonZeroU8) -> Filter {
        Self::check_cpu_support();
        assert!(
            qbits.get() + rbits.get() <= 64,
            "Capacity + false positive rate overflows 64 bit hashes"
        );
        let num_slots = 1 << qbits.get();
        let num_blocks = num_slots / 64;
        assert!(num_blocks != 0);
        let block_bytes_size = 1 + 16 + 64 * rbits.u64() / 8;
        let buffer_bytes = num_blocks * block_bytes_size;
        let buffer = vec![0u8; buffer_bytes.try_into().unwrap()];
        Self {
            buffer,
            qbits,
            rbits,
            len: 0,
        }
    }

    fn check_cpu_support() {
        #[cfg(all(
            target_arch = "x86_64",
            not(feature = "legacy_x86_64_support"),
            not(target_feature = "popcnt")
        ))]
        assert!(
            std::is_x86_feature_detected!("popcnt"),
            "CPU doesn't support the popcnt instruction"
        );
    }

    /// Whether the filter is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Current number of items admitted to the filter.
    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Resets/Clears the filter.
    pub fn clear(&mut self) {
        self.buffer.fill(0);
        self.len = 0;
    }

    /// Current filter capacity.
    #[inline]
    pub fn capacity(&self) -> u64 {
        if cfg!(fuzzing) {
            // 100% occupancy is not realistic but stresses the algorithm much more.
            // To generate real counter examples this "pessimisation" must be removed.
            self.total_buckets().get()
        } else {
            // Up to 95% occupancy
            // 19/20 == 0.95
            // Overflow is not possible here as it'd have overflowed in the constructor.
            self.total_buckets().get() * 19 / 20
        }
    }

    /// Max error ratio when at full capacity (len == capacity).
    pub fn max_error_ratio(&self) -> f64 {
        2f64.powi(-(self.rbits.get() as i32))
    }

    /// Current error ratio at the current occupancy.
    pub fn current_error_ratio(&self) -> f64 {
        let occupancy = self.len as f64 / self.total_buckets().get() as f64;
        1.0 - std::f64::consts::E.powf(-occupancy / 2f64.powi(self.rbits.get() as i32))
    }

    #[inline]
    fn block_byte_size(&self) -> usize {
        1 + 8 + 8 + 64 * self.rbits.usize() / 8
    }

    #[inline]
    fn set_block_runends(&mut self, block_num: u64, runends: u64) {
        let block_num = block_num % self.total_blocks();
        let block_start = block_num as usize * self.block_byte_size();
        let block_bytes: &mut [u8; 1 + 8 + 8] = (&mut self.buffer[block_start..][..1 + 8 + 8])
            .try_into()
            .unwrap();
        block_bytes[1 + 8..1 + 8 + 8].copy_from_slice(&runends.to_le_bytes());
    }

    #[inline]
    fn raw_block(&self, block_num: u64) -> Block {
        let block_num = block_num % self.total_blocks();
        let block_start = block_num as usize * self.block_byte_size();
        let block_bytes: &[u8; 1 + 8 + 8] =
            &self.buffer[block_start..][..1 + 8 + 8].try_into().unwrap();
        Block {
            offset: block_bytes[0] as u64,
            occupieds: u64::from_le_bytes(block_bytes[1..1 + 8].try_into().unwrap()),
            runends: u64::from_le_bytes(block_bytes[1 + 8..1 + 8 + 8].try_into().unwrap()),
        }
    }

    #[inline]
    fn block(&self, block_num: u64) -> Block {
        let block_num = block_num % self.total_blocks();
        let block_start = block_num as usize * self.block_byte_size();
        let block_bytes: &[u8; 1 + 8 + 8] = &self.buffer[block_start..block_start + 1 + 8 + 8]
            .try_into()
            .unwrap();
        let offset = {
            if block_bytes[0] < u8::MAX {
                block_bytes[0] as u64
            } else {
                self.calc_offset(block_num)
            }
        };
        Block {
            offset,
            occupieds: u64::from_le_bytes(block_bytes[1..1 + 8].try_into().unwrap()),
            runends: u64::from_le_bytes(block_bytes[1 + 8..1 + 8 + 8].try_into().unwrap()),
        }
    }

    #[inline]
    fn adjust_block_offset(&mut self, block_num: u64, inc: bool) {
        let block_num = block_num % self.total_blocks();
        let block_start = block_num as usize * self.block_byte_size();
        let offset = &mut self.buffer[block_start];
        if inc {
            *offset = offset.saturating_add(1);
        } else if *offset != u8::MAX {
            *offset -= 1;
        } else {
            self.buffer[block_start] = self.calc_offset(block_num).try_into().unwrap_or(u8::MAX);
        }
    }

    #[inline]
    fn inc_offsets(&mut self, start_bucket: u64, end_bucket: u64) {
        let original_block = start_bucket / 64;
        let mut last_affected_block = end_bucket / 64;
        if end_bucket < start_bucket {
            last_affected_block += self.total_blocks().get();
        }
        for b in original_block + 1..=last_affected_block {
            self.adjust_block_offset(b, true);
        }
    }

    #[inline]
    fn dec_offsets(&mut self, start_bucket: u64, end_bucket: u64) {
        let original_block = start_bucket / 64;
        let mut last_affected_block = end_bucket / 64;
        if end_bucket < start_bucket {
            last_affected_block += self.total_blocks().get();
        }

        // As an edge case we may decrement the offsets of 2+ blocks and the block B' offset
        // may be saturated and depend on a previous Block B" with a non saturated offset.
        // But B" offset may also(!) be affected by the decremented operation, so we must
        // decrement B" offset first before the remaining offsets.
        if last_affected_block > original_block + 1 // 2+ blocks check
            && self.raw_block(original_block + 1).offset >= u8::MAX as u64
        {
            // last affected block offset is always <= 64 (BLOCK SIZE)
            // otherwise the decrement operation would be to affecting a subsequent block
            debug_assert!(self.raw_block(last_affected_block).offset <= 64);
            self.adjust_block_offset(last_affected_block, false);
            last_affected_block -= 1;
        }
        for b in original_block + 1..=last_affected_block {
            self.adjust_block_offset(b, false);
        }

        #[cfg(fuzzing)]
        self.validate_offsets(original_block, last_affected_block);
    }

    #[cfg(any(fuzzing, test))]
    fn validate_offsets(&mut self, original_block: u64, last_affected_block: u64) {
        for b in original_block..=last_affected_block {
            let raw_offset = self.raw_block(b).offset;
            let offset = self.calc_offset(b);
            debug_assert!(
                (raw_offset >= u8::MAX as u64 && offset >= u8::MAX as u64)
                    || (offset == raw_offset),
                "block {} offset {} calc {}",
                b,
                raw_offset,
                offset,
            );
        }
    }

    #[inline(always)]
    fn is_occupied(&self, hash_bucket_idx: u64) -> bool {
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let block_start = (hash_bucket_idx / 64) as usize * self.block_byte_size();
        let occupieds = u64::from_le_bytes(
            self.buffer[block_start + 1..block_start + 1 + 8]
                .try_into()
                .unwrap(),
        );
        occupieds.is_bit_set((hash_bucket_idx % 64) as usize)
    }

    #[inline(always)]
    fn set_occupied(&mut self, hash_bucket_idx: u64, value: bool) {
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let block_start = (hash_bucket_idx / 64) as usize * self.block_byte_size();
        let mut occupieds = u64::from_le_bytes(
            self.buffer[block_start + 1..block_start + 1 + 8]
                .try_into()
                .unwrap(),
        );
        occupieds.update_bit((hash_bucket_idx % 64) as usize, value);
        self.buffer[block_start + 1..block_start + 1 + 8].copy_from_slice(&occupieds.to_le_bytes());
    }

    #[inline(always)]
    fn is_runend(&self, hash_bucket_idx: u64) -> bool {
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let block_start = (hash_bucket_idx / 64) as usize * self.block_byte_size();
        let runends = u64::from_le_bytes(
            self.buffer[block_start + 1 + 8..block_start + 1 + 8 + 8]
                .try_into()
                .unwrap(),
        );
        runends.is_bit_set((hash_bucket_idx % 64) as usize)
    }

    #[inline(always)]
    fn set_runend(&mut self, hash_bucket_idx: u64, value: bool) {
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let block_start = (hash_bucket_idx / 64) as usize * self.block_byte_size();
        let mut runends = u64::from_le_bytes(
            self.buffer[block_start + 1 + 8..block_start + 1 + 8 + 8]
                .try_into()
                .unwrap(),
        );
        runends.update_bit((hash_bucket_idx % 64) as usize, value);
        self.buffer[block_start + 1 + 8..block_start + 1 + 8 + 8]
            .copy_from_slice(&runends.to_le_bytes());
    }

    #[inline(always)]
    fn get_remainder(&self, hash_bucket_idx: u64) -> u64 {
        debug_assert!(self.rbits.get() > 0 && self.rbits.get() < 64);
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let remainders_start = (hash_bucket_idx / 64) as usize * self.block_byte_size() + 1 + 8 + 8;
        let start_bit_idx = self.rbits.usize() * (hash_bucket_idx % 64) as usize;
        let end_bit_idx = start_bit_idx + self.rbits.usize();
        let start_u64 = start_bit_idx / 64;
        let num_rem_parts = 1 + (end_bit_idx > (start_u64 + 1) * 64) as usize;
        let rem_parts_bytes = &self.buffer[remainders_start + start_u64 * 8..][..num_rem_parts * 8];
        let extra_low = start_bit_idx - start_u64 * 64;
        let extra_high = ((start_u64 + 1) * 64).saturating_sub(end_bit_idx);
        let rem_part = u64::from_le_bytes(rem_parts_bytes[..8].try_into().unwrap());
        // zero high bits & truncate low bits
        let mut remainder = (rem_part << extra_high) >> (extra_high + extra_low);
        if let Some(rem_part) = rem_parts_bytes.get(8..16) {
            let remaining_bits = end_bit_idx - (start_u64 + 1) * 64;
            let rem_part = u64::from_le_bytes(rem_part.try_into().unwrap());
            remainder |=
                (rem_part & !(u64::MAX << remaining_bits)) << (self.rbits.usize() - remaining_bits);
        }
        debug_assert!(remainder.leading_zeros() >= 64 - self.rbits.get() as u32);
        remainder
    }

    #[inline(always)]
    fn set_remainder(&mut self, hash_bucket_idx: u64, remainder: u64) {
        debug_assert!(self.rbits.get() > 0 && self.rbits.get() < 64);
        debug_assert!(remainder.leading_zeros() >= 64 - self.rbits.get() as u32);
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let remainders_start = (hash_bucket_idx / 64) as usize * self.block_byte_size() + 1 + 8 + 8;
        let start_bit_idx = self.rbits.usize() * (hash_bucket_idx % 64) as usize;
        let end_bit_idx = start_bit_idx + self.rbits.usize();
        let start_u64 = start_bit_idx / 64;
        let num_rem_parts = 1 + (end_bit_idx > (start_u64 + 1) * 64) as usize;
        let rem_parts_bytes =
            &mut self.buffer[remainders_start + start_u64 * 8..][..num_rem_parts * 8];
        let mut rem_part = u64::from_le_bytes(rem_parts_bytes[..8].try_into().unwrap());
        let extra_low = start_bit_idx - start_u64 * 64;
        let extra_high = ((start_u64 + 1) * 64).saturating_sub(end_bit_idx);
        // zero region we'll copy remainder bits in
        rem_part &= !((u64::MAX << extra_low) & (u64::MAX >> extra_high));
        let low_bits_to_copy = 64 - extra_high - extra_low;
        rem_part |= (remainder & !(u64::MAX << low_bits_to_copy)) << extra_low;
        rem_parts_bytes[..8].copy_from_slice(&rem_part.to_le_bytes());
        if rem_parts_bytes.len() < 16 {
            return;
        }

        let remaining_bits = end_bit_idx - (start_u64 + 1) * 64;
        rem_part = u64::from_le_bytes(rem_parts_bytes[8..16].try_into().unwrap());
        // zero region we'll copy remainder bits in
        rem_part &= u64::MAX << remaining_bits;
        rem_part |= remainder >> (self.rbits.usize() - remaining_bits);
        rem_parts_bytes[8..16].copy_from_slice(&rem_part.to_le_bytes());
    }

    #[inline]
    fn get_rem_u64(&self, rem_u64: u64) -> u64 {
        let rbits = NonZeroU64::try_from(self.rbits).unwrap();
        let bucket_block_idx = (rem_u64 / rbits) % self.total_blocks();
        let bucket_rem_u64 = (rem_u64 % rbits) as usize;
        let bucket_rem_start = (bucket_block_idx as usize * self.block_byte_size()) + 1 + 8 + 8;
        u64::from_le_bytes(
            self.buffer[bucket_rem_start + bucket_rem_u64 * 8..][..8]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn set_rem_u64(&mut self, rem_u64: u64, rem: u64) {
        let rbits = NonZeroU64::try_from(self.rbits).unwrap();
        let bucket_block_idx = (rem_u64 / rbits) % self.total_blocks();
        let bucket_rem_u64 = (rem_u64 % rbits) as usize;
        let bucket_rem_start = (bucket_block_idx as usize * self.block_byte_size()) + 1 + 8 + 8;
        self.buffer[bucket_rem_start + bucket_rem_u64 * 8..][..8]
            .copy_from_slice(&rem.to_le_bytes());
    }

    fn shift_remainders_by_1(&mut self, start: u64, end_inc: u64) {
        let end = if end_inc < start {
            end_inc + self.total_buckets().get() + 1
        } else {
            end_inc + 1
        };
        let mut end_u64 = end * self.rbits.u64() / 64;
        let mut bend = (end * self.rbits.u64() % 64) as usize;
        let start_u64 = start * self.rbits.u64() / 64;
        let bstart = (start * self.rbits.u64() % 64) as usize;
        while end_u64 != start_u64 {
            let prev_rem_u64 = self.get_rem_u64(end_u64 - 1);
            let mut rem_u64 = self.get_rem_u64(end_u64);
            rem_u64 = prev_rem_u64.shift_right(self.rbits.usize(), &rem_u64, 0, bend);
            self.set_rem_u64(end_u64, rem_u64);
            end_u64 -= 1;
            bend = 64;
        }
        let mut rem_u64 = self.get_rem_u64(start_u64);
        rem_u64 = 0u64.shift_right(self.rbits.usize(), &rem_u64, bstart, bend);
        self.set_rem_u64(start_u64, rem_u64);
    }

    fn shift_remainders_back_by_1(&mut self, start: u64, end_inc: u64) {
        let end = if end_inc < start {
            end_inc + self.total_buckets().get() + 1
        } else {
            end_inc + 1
        };
        let end_u64 = end * self.rbits.u64() / 64;
        let bend = (end * self.rbits.u64() % 64) as usize;
        let mut start_u64 = start * self.rbits.u64() / 64;
        let mut bstart = (start * self.rbits.u64() % 64) as usize;
        while end_u64 != start_u64 {
            let next_rem_u64 = self.get_rem_u64(start_u64 + 1);
            let mut rem_u64 = self.get_rem_u64(start_u64);
            rem_u64 = next_rem_u64.shift_left(self.rbits.usize(), &rem_u64, bstart, 64);
            self.set_rem_u64(start_u64, rem_u64);
            start_u64 += 1;
            bstart = 0;
        }
        let mut rem_u64 = self.get_rem_u64(end_u64);
        rem_u64 = 0u64.shift_left(self.rbits.usize(), &rem_u64, bstart, bend);
        self.set_rem_u64(end_u64, rem_u64);
    }

    fn shift_runends_by_1(&mut self, start: u64, end_inc: u64) {
        let end = if end_inc < start {
            end_inc + self.total_buckets().get() + 1
        } else {
            end_inc + 1
        };
        let mut end_block = end / 64;
        let mut bend = (end % 64) as usize;
        let start_block = start / 64;
        let bstart = (start % 64) as usize;
        while end_block != start_block {
            let prev_block_runends = self.raw_block(end_block - 1).runends;
            let mut block_runends = self.raw_block(end_block).runends;
            block_runends = prev_block_runends.shift_right(1, &block_runends, 0, bend);
            self.set_block_runends(end_block, block_runends);
            end_block -= 1;
            bend = 64;
        }
        let mut block_runends = self.raw_block(start_block).runends;
        block_runends = 0u64.shift_right(1, &block_runends, bstart, bend);
        self.set_block_runends(start_block, block_runends);
    }

    fn shift_runends_back_by_1(&mut self, start: u64, end_inc: u64) {
        let end = if end_inc < start {
            end_inc + self.total_buckets().get() + 1
        } else {
            end_inc + 1
        };
        let end_block = end / 64;
        let bend = (end % 64) as usize;
        let mut start_block = start / 64;
        let mut bstart = (start % 64) as usize;
        while start_block != end_block {
            let next_block_runends = self.raw_block(start_block + 1).runends;
            let mut block_runends = self.raw_block(start_block).runends;
            block_runends = next_block_runends.shift_left(1, &block_runends, bstart, 64);
            self.set_block_runends(start_block, block_runends);
            start_block += 1;
            bstart = 0;
        }
        let mut block_runends = self.raw_block(end_block).runends;
        block_runends = 0u64.shift_left(1, &block_runends, bstart, bend);
        self.set_block_runends(end_block, block_runends);
    }

    #[cold]
    #[inline(never)]
    fn calc_offset(&self, block_num: u64) -> u64 {
        // The block offset can be calculated as the difference between its position and runstart.
        let block_start = (block_num * 64) % self.total_buckets();
        let mut run_start = self.run_start(block_start);
        if run_start < block_start {
            run_start += self.total_buckets().get();
        }
        run_start - block_start
    }

    /// Start idx of of the run (inclusive)
    #[inline]
    fn run_start(&self, hash_bucket_idx: u64) -> u64 {
        // runstart is equivalent to the runend of the previous bucket + 1.
        let prev_bucket = hash_bucket_idx.wrapping_sub(1) % self.total_buckets();
        (self.run_end(prev_bucket) + 1) % self.total_buckets()
    }

    /// End idx of the end of the run (inclusive).
    fn run_end(&self, hash_bucket_idx: u64) -> u64 {
        let hash_bucket_idx = hash_bucket_idx % self.total_buckets();
        let bucket_block_idx = hash_bucket_idx / 64;
        let bucket_intrablock_offset = hash_bucket_idx % 64;
        let bucket_block = self.block(bucket_block_idx);
        let bucket_intrablock_rank = bucket_block.occupieds.popcnt(..=bucket_intrablock_offset);
        // No occupied buckets all the way to bucket_intrablock_offset
        // which also means hash_bucket_idx isn't occupied
        if bucket_intrablock_rank == 0 {
            return if bucket_block.offset <= bucket_intrablock_offset {
                // hash_bucket_idx points to an empty bucket unaffected by block offset,
                // thus end == start
                hash_bucket_idx
            } else {
                // hash_bucket_idx fall within the section occupied by the offset,
                // thus end == last bucket of offset section
                (bucket_block_idx * 64 + bucket_block.offset - 1) % self.total_buckets()
            };
        }

        // Must search runends to figure out the end of the run
        let mut runend_block_idx = bucket_block_idx + bucket_block.offset / 64;
        let mut runend_ignore_bits = bucket_block.offset % 64;
        let mut runend_block = self.raw_block(runend_block_idx);
        // Try to find the runend for the bucket in this block.
        // We're looking for the runend_rank'th bit set (0 based)
        let mut runend_rank = bucket_intrablock_rank - 1;
        let mut runend_block_offset = runend_block
            .runends
            .select(runend_ignore_bits.., runend_rank);

        if let Some(runend_block_offset) = runend_block_offset {
            let runend_idx = runend_block_idx * 64 + runend_block_offset;
            return runend_idx.max(hash_bucket_idx) % self.total_buckets();
        }
        // There were not enough runend bits set, keep looking...
        loop {
            // subtract any runend bits found
            runend_rank -= runend_block.runends.popcnt(runend_ignore_bits..);
            // move to the next block
            runend_block_idx += 1;
            runend_ignore_bits = 0;
            runend_block = self.raw_block(runend_block_idx);
            runend_block_offset = runend_block
                .runends
                .select(runend_ignore_bits.., runend_rank);

            if let Some(runend_block_offset) = runend_block_offset {
                let runend_idx = runend_block_idx * 64 + runend_block_offset;
                return runend_idx.max(hash_bucket_idx) % self.total_buckets();
            }
        }
    }

    /// Returns whether item is present (probabilistically) in the filter.
    pub fn contains<T: Hash>(&self, item: T) -> bool {
        self.do_contains(Self::hash(item))
    }

    fn do_contains(&self, hash: u64) -> bool {
        let (hash_bucket_idx, hash_remainder) = self.calc_qr(hash);
        if !self.is_occupied(hash_bucket_idx) {
            return false;
        }
        let mut runstart_idx = self.run_start(hash_bucket_idx);
        // dbg!(hash_bucket_idx, runstart_idx);
        loop {
            if hash_remainder == self.get_remainder(runstart_idx) {
                return true;
            }
            if self.is_runend(runstart_idx) {
                return false;
            }
            runstart_idx += 1;
        }
    }

    #[doc(hidden)]
    #[cfg(any(fuzzing, test))]
    pub fn count<T: Hash>(&mut self, item: T) -> u64 {
        let hash = Self::hash(item);
        let (hash_bucket_idx, hash_remainder) = self.calc_qr(hash);
        if !self.is_occupied(hash_bucket_idx) {
            return 0;
        }

        let mut count = 0u64;
        let mut runstart_idx = self.run_start(hash_bucket_idx);
        loop {
            if hash_remainder == self.get_remainder(runstart_idx) {
                count += 1;
            }
            if self.is_runend(runstart_idx) {
                return count;
            }
            runstart_idx += 1;
        }
    }

    #[inline]
    fn offset_lower_bound(&self, hash_bucket_idx: u64) -> u64 {
        let bucket_block_idx = hash_bucket_idx / 64;
        let bucket_intrablock_offset = hash_bucket_idx % 64;
        let bucket_block = self.raw_block(bucket_block_idx);
        let num_occupied = bucket_block.occupieds.popcnt(..=bucket_intrablock_offset);
        if bucket_block.offset <= bucket_intrablock_offset {
            num_occupied
                - bucket_block
                    .runends
                    .popcnt(bucket_block.offset..bucket_intrablock_offset)
        } else {
            bucket_block.offset + num_occupied - bucket_intrablock_offset
        }
    }

    fn find_first_empty_slot(&self, mut hash_bucket_idx: u64) -> u64 {
        loop {
            let olb = self.offset_lower_bound(hash_bucket_idx);
            if olb == 0 {
                return hash_bucket_idx % self.total_buckets();
            }
            hash_bucket_idx += olb;
        }
    }

    fn find_first_not_shifted_slot(&self, mut hash_bucket_idx: u64) -> u64 {
        loop {
            let run_end = self.run_end(hash_bucket_idx);
            if run_end == hash_bucket_idx {
                return hash_bucket_idx;
            }
            hash_bucket_idx = run_end;
        }
    }

    /// Removes `item` from the filter.
    /// Returns whether item was actually found and removed.
    ///
    /// Note that removing an item who wasn't previously added to the filter
    /// may introduce false negatives. This is because it could be removing
    /// fingerprints from a colliding item!
    pub fn remove<T: Hash>(&mut self, item: T) -> bool {
        self.do_remove(Self::hash(item))
    }

    fn do_remove(&mut self, hash: u64) -> bool {
        let (hash_bucket_idx, hash_remainder) = self.calc_qr(hash);
        if !self.is_occupied(hash_bucket_idx) {
            return false;
        }
        let mut run_start = self.run_start(hash_bucket_idx);
        // adjust run_start so we can have
        // hash_bucket_idx <= run_start <= found_idx <= run_end
        if run_start < hash_bucket_idx {
            run_start += self.total_buckets().get();
        }
        let mut run_end = run_start;
        let mut found_idx = None;
        let found_idx = loop {
            if hash_remainder == self.get_remainder(run_end) {
                found_idx = Some(run_end);
            }
            if self.is_runend(run_end) {
                if let Some(i) = found_idx {
                    break i;
                } else {
                    return false;
                };
            }
            run_end += 1;
        };

        let mut last_bucket_shifted_run_end = run_end;
        if last_bucket_shifted_run_end != hash_bucket_idx {
            last_bucket_shifted_run_end = self.find_first_not_shifted_slot(run_end);
            if last_bucket_shifted_run_end < run_end {
                last_bucket_shifted_run_end += self.total_buckets().get();
            }
        }

        // run_end points to the end of the run (inc) which contains the target remainder (found_idx)
        // If we had a single remainder in the run the run is no more
        if run_end == run_start {
            self.set_occupied(hash_bucket_idx, false);
        } else {
            // More than one remainder in the run.
            // If the removed rem is the last one in the run
            // the before last remainder becomes the new runend.
            if found_idx == run_end {
                self.set_runend(run_end - 1, true);
            }
        }
        if found_idx != last_bucket_shifted_run_end {
            self.set_remainder(found_idx, 0);
            self.shift_remainders_back_by_1(found_idx, last_bucket_shifted_run_end);
            self.shift_runends_back_by_1(found_idx, last_bucket_shifted_run_end);
        }
        self.set_runend(last_bucket_shifted_run_end, false);
        self.set_remainder(last_bucket_shifted_run_end, 0);
        self.dec_offsets(hash_bucket_idx, last_bucket_shifted_run_end);
        self.len -= 1;
        true
    }

    /// Inserts `item` in the filter, even if already appears to be in the filter.
    /// This works by inserting a possibly duplicated fingerprint in the filter.
    ///
    /// This function should be used when the filter is also subject to removals
    /// and the item is known to not have been added to the filter before (or was removed).
    pub fn insert_duplicated<T: Hash>(&mut self, item: T) -> Result<(), QError> {
        let hash = Self::hash(item);
        self.do_insert(true, hash).map(|_| ())
    }

    /// Inserts `item` in the filter.
    /// Returns ok(true) if the item was successfully added to the filter.
    /// Returns ok(false) if the item is already contained (probabilistically) in the filter.
    /// Returns an error if the filter cannot admit the new item.
    pub fn insert<T: Hash>(&mut self, item: T) -> Result<bool, QError> {
        let hash = Self::hash(item);
        self.do_insert(false, hash)
    }

    fn do_insert(&mut self, duplicate: bool, hash: u64) -> Result<bool, QError> {
        enum Operation {
            NewRun,
            BeforeRunend,
            NewRunend,
        }

        let (hash_bucket_idx, hash_remainder) = self.calc_qr(hash);
        if self.offset_lower_bound(hash_bucket_idx) == 0 {
            if self.len >= self.capacity() {
                return Err(QError::CapacityExceeded);
            }
            debug_assert!(!self.is_occupied(hash_bucket_idx));
            debug_assert!(!self.is_runend(hash_bucket_idx));
            self.set_occupied(hash_bucket_idx, true);
            self.set_runend(hash_bucket_idx, true);
            self.set_remainder(hash_bucket_idx, hash_remainder);
            self.len += 1;
            return Ok(true);
        }

        let mut runstart_idx = self.run_start(hash_bucket_idx);
        let mut runend_idx = self.run_end(hash_bucket_idx);
        let insert_idx;
        let operation;
        if self.is_occupied(hash_bucket_idx) {
            // adjust runend so its >= runstart even if it wrapped around
            if runend_idx < runstart_idx {
                runend_idx += self.total_buckets().get();
            }
            while runstart_idx <= runend_idx {
                match self.get_remainder(runstart_idx).cmp(&hash_remainder) {
                    Ordering::Less => (), // TODO: sorted hashes appears to have no positive impact
                    Ordering::Equal if duplicate => (),
                    Ordering::Equal => return Ok(false),
                    Ordering::Greater => break,
                }

                runstart_idx += 1;
            }

            if runstart_idx > runend_idx {
                /* new remainder is >= than any remainder in the run. */
                operation = Operation::NewRunend;
                insert_idx = runstart_idx % self.total_buckets();
            } else {
                /* there are larger remainders already in the run. */
                operation = Operation::BeforeRunend; /* Inserting */
                insert_idx = runstart_idx % self.total_buckets();
            }
        } else {
            insert_idx = (runend_idx + 1) % self.total_buckets();
            operation = Operation::NewRun; /* Insert into empty bucket */
        }

        if self.len >= self.capacity() {
            return Err(QError::CapacityExceeded);
        }
        let empty_slot_idx = self.find_first_empty_slot(runend_idx + 1);
        if insert_idx != empty_slot_idx {
            self.shift_remainders_by_1(insert_idx, empty_slot_idx);
            self.shift_runends_by_1(insert_idx, empty_slot_idx);
        }
        self.set_remainder(insert_idx, hash_remainder);
        match operation {
            Operation::NewRun => {
                /* Insert into empty bucket */
                self.set_runend(insert_idx, true);
                self.set_occupied(hash_bucket_idx, true);
            }
            Operation::NewRunend => {
                /*  new remainder it is >= than any remainder in the run. */
                self.set_runend(insert_idx.wrapping_sub(1) % self.total_buckets(), false);
                self.set_runend(insert_idx, true);
            }
            Operation::BeforeRunend => { /* there are larger remainders already in the run. */ }
        }

        self.inc_offsets(hash_bucket_idx, empty_slot_idx);
        self.len += 1;
        Ok(true)
    }

    #[inline]
    pub fn hash<T: Hash>(item: T) -> u64 {
        let mut hasher = StableHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    fn calc_qr(&self, hash: u64) -> (u64, u64) {
        let hash_bucket_idx = (hash >> self.rbits.get()) & ((1 << self.qbits.get()) - 1);
        let remainder = hash & ((1 << self.rbits.get()) - 1);
        (hash_bucket_idx, remainder)
    }

    #[inline]
    fn total_blocks(&self) -> NonZeroU64 {
        // The way this is calculated ensures the compilers sees that the result is both != 0 and a power of 2,
        // both of which allow the optimizer to generate much faster division/remainder code.
        #[cfg(any(debug_assertions, fuzzing))]
        {
            NonZeroU64::new((1u64 << self.qbits.get()) / 64).unwrap()
        }
        #[cfg(not(any(debug_assertions, fuzzing)))]
        {
            // Safety: All filter have at least 1 block (which have 64 slots each)
            unsafe { NonZeroU64::new_unchecked((1u64 << self.qbits.get()) / 64) }
        }
    }

    #[inline]
    fn total_buckets(&self) -> NonZeroU64 {
        NonZeroU64::new(1 << self.qbits.get()).unwrap()
    }

    #[doc(hidden)]
    #[cfg(any(fuzzing, test))]
    pub fn printout(&self) {
        eprintln!(
            "=== q {} r {} len {} cap {} ===",
            self.qbits,
            self.rbits,
            self.len(),
            self.capacity()
        );
        for b in 0..self.total_blocks().get() {
            let block = self.raw_block(b);
            eprintln!(
                "block {} offset {:?}\noccup {:064b}\nrunen {:064b}",
                b, block.offset, block.occupieds, block.runends
            );
            eprintln!(
                "      3210987654321098765432109876543210987654321098765432109876543210 {}",
                b * 64
            );
            eprint!("rem   ");
            for i in (0..64).rev() {
                let r = self.get_remainder(b * 64 + i);
                eprint!("{}", r % 100 / 10);
            }
            eprint!("\nrem   ");
            for i in (0..64).rev() {
                let r = self.get_remainder(b * 64 + i);
                eprint!("{}", r % 10);
            }
            println!("");
        }
        eprintln!("===");
    }
    
    fn save_to_db(&self, db: &Db, shard_id: usize, filter_id: usize) -> Result<(), Error> {
        debug!("Saving filter {} of shard {} to disk", filter_id, shard_id);
        let value = to_bytes::<_, 1024>(self).map_err(|_| Error::SerializationError)?;
        let key = [
            b"filter_",
            shard_id.to_be_bytes().as_ref(),
            filter_id.to_be_bytes().as_ref(),
        ]
        .concat();
        db.insert(key, value.as_ref())?;
        Ok(())
    }
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter")
            .field("buffer", &"[..]")
            .field("len", &self.len)
            .field("qbits", &self.qbits)
            .field("rbits", &self.rbits)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_end_simple() {
        let mut f = Filter::new(50, 0.01);
        f.set_occupied(5, true);
        f.set_runend(5, true);
        assert_eq!(f.run_end(4), 4);
        assert_eq!(f.run_end(5), 5);
        assert_eq!(f.run_end(6), 6);

        f.set_occupied(6, true);
        f.set_runend(6, true);
        assert_eq!(f.run_end(4), 4);
        assert_eq!(f.run_end(5), 5);
        assert_eq!(f.run_end(6), 6);

        f.set_runend(6, false);
        f.set_runend(7, true);
        assert_eq!(f.run_end(4), 4);
        assert_eq!(f.run_end(5), 5);
        assert_eq!(f.run_end(6), 7);

        f.set_runend(7, false);
        f.set_runend(8, true);
        assert_eq!(f.run_end(4), 4);
        assert_eq!(f.run_end(5), 5);
        assert_eq!(f.run_end(6), 8);

        f.set_occupied(10, true);
        f.set_runend(12, true);
        f.set_occupied(12, true);
        f.set_runend(13, true);
        assert_eq!(f.run_end(10), 12);
        assert_eq!(f.run_end(12), 13);

        f.set_occupied(11, true);
        f.set_runend(14, true);
        assert_eq!(f.run_end(10), 12);
        assert_eq!(f.run_end(11), 13);
        assert_eq!(f.run_end(12), 14);
    }

    #[test]
    fn run_end_eob() {
        let mut f = Filter::new(50, 0.01);
        assert_eq!(f.total_buckets().get(), 64);
        f.set_occupied(63, true);
        f.set_runend(63, true);
        assert_eq!(f.run_end(62), 62);
        assert_eq!(f.run_end(63), 63);
        assert_eq!(f.find_first_empty_slot(62), 62);
        assert_eq!(f.find_first_empty_slot(63), 0);
    }

    #[test]
    fn run_end_crossing() {
        let mut f = Filter::new(50, 0.01);
        f.set_occupied(0, true);
        f.set_runend(0, true);
        f.set_occupied(63, true);
        f.set_runend(63, true);
        assert_eq!(f.run_end(0), 0);
        assert_eq!(f.run_end(1), 1);
        assert_eq!(f.run_end(62), 62);
        assert_eq!(f.run_end(63), 63);

        f.set_runend(63, false);
        f.set_runend(1, true);
        f.adjust_block_offset(1, true);
        assert_eq!(f.run_end(0), 1);
        assert_eq!(f.run_end(1), 1);
        assert_eq!(f.run_end(62), 62);
        assert_eq!(f.run_end(63), 0);

        f.set_runend(1, false);
        f.set_runend(2, true);
        assert_eq!(f.run_end(63), 0);
        assert_eq!(f.run_end(0), 2);
        assert_eq!(f.run_end(1), 2);

        f.set_runend(2, false);
        f.set_runend(3, true);
        assert_eq!(f.run_end(63), 0);
        assert_eq!(f.run_end(1), 3);
        assert_eq!(f.run_end(2), 3);

        f.set_occupied(65, true);
        f.set_runend(68, true);
        assert_eq!(f.run_end(63), 0);
        assert_eq!(f.run_end(0), 3);
        assert_eq!(f.run_end(1), 4);
    }

    #[test]
    fn test_insert_duplicated() {
        for cap in [100, 200, 500, 1000] {
            let mut f = Filter::new(cap, 0.01);
            for i in 0..f.capacity() / 2 {
                f.insert_duplicated(-1).unwrap();
                f.insert_duplicated(i).unwrap();
                assert!(f.count(-1) >= i);
                assert!(f.count(i) >= 1);
            }
        }
    }

    #[test]
    fn test_insert_duplicated_two() {
        for s in 0..10 {
            for c in [200, 800, 1500] {
                let mut f = Filter::new(c, 0.001);
                for i in 0..f.capacity() / 2 {
                    f.insert_duplicated(-1).unwrap();
                    assert_eq!(f.count(-1), i as u64 + 1);
                    assert_eq!(f.count(s), i as u64);
                    f.insert_duplicated(s).unwrap();
                    assert_eq!(f.count(-1), i as u64 + 1);
                    assert_eq!(f.count(s), i as u64 + 1);
                }
            }
        }
    }

    #[test]
    fn test_insert_duplicated_one() {
        for s in 0..10 {
            for cap in [100, 200, 500, 1000] {
                let mut f = Filter::new(cap, 0.01);
                for i in 0..f.capacity() {
                    f.insert_duplicated(s).unwrap();
                    assert!(f.count(s) >= i + 1);
                }
                assert_eq!(f.count(s), f.capacity());
            }
        }
    }

    #[test]
    #[should_panic]
    fn test_new_capacity_overflow() {
        Filter::new(u64::MAX, 0.01);
    }

    #[test]
    #[should_panic]
    fn test_new_hash_overflow() {
        Filter::new(u64::MAX / 20, 0.01);
    }

    #[test]
    fn test_remainders_and_shifts() {
        let mut f = Filter::new(200, 0.01);
        let c = f.capacity();
        for j in 0..c {
            f.set_remainder(j, 0b1011101);
            assert_eq!(f.get_remainder(j), 0b1011101);
            f.set_runend(j, true);
            assert!(f.is_runend(j));
        }
        for j in 0..c {
            f.set_remainder(j, 0b1111111);
            assert_eq!(f.get_remainder(j), 0b1111111);
            f.set_runend(j, false);
            assert!(!f.is_runend(j));
        }
        for j in 0..c {
            f.set_remainder(j, 0b1101101);
            assert_eq!(f.get_remainder(j), 0b1101101);
            f.set_runend(j, true);
            assert!(f.is_runend(j));
        }
        f.shift_remainders_by_1(0, c);
        f.shift_runends_by_1(0, c);

        for j in 1..=c {
            assert_eq!(f.get_remainder(j), 0b1101101);
        }
        assert!(!f.is_runend(0));
        for j in 1..=c {
            assert_eq!(f.get_remainder(j), 0b1101101);
            assert!(f.is_runend(j));
        }
    }

    #[test]
    fn test_remove() {
        for fp in [0.0001, 0.00001, 0.000001] {
            for cap in [0, 100, 200, 400, 1000] {
                // for cap in [0] {
                let mut f = Filter::new(cap, fp);
                dbg!(f.rbits, f.capacity());
                let c = f.capacity();
                for i in 0..c {
                    assert!(f.insert(i).unwrap());
                }
                assert_eq!(f.len() as u64, c);
                for i in 0..c {
                    for j in 0..c {
                        assert_eq!(f.count(j), (j >= i) as u64, "{}", j);
                    }
                    // f.printout();
                    assert!(f.remove(i));
                    // f.printout();
                }
                assert!(f.is_empty());
            }
        }
    }
    #[test]
    fn test_remove_dup_one() {
        for s in 0..10 {
            for cap in [0, 100, 200, 500, 1000] {
                let mut f = Filter::new(cap, 0.0001);
                let c = f.capacity();
                for _ in 0..c {
                    f.insert_duplicated(s).unwrap();
                }
                assert_eq!(f.len() as u64, c);
                for i in 0..c {
                    assert_eq!(f.count(s), c - i);
                    assert!(f.remove(s));
                }
                assert!(f.is_empty());
            }
        }
    }
    #[test]
    fn test_remove_dup_two() {
        for s in 0..10 {
            dbg!(s);
            for cap in [100, 200, 500, 1000] {
                let mut f = Filter::new(cap, 0.0001);
                let c = f.capacity();
                for _ in 0..c / 2 {
                    f.insert_duplicated(-1).unwrap();
                    f.insert_duplicated(s).unwrap();
                }
                assert_eq!(f.count(-1), c / 2);
                assert_eq!(f.count(s), c / 2);
                for i in 0..c / 2 {
                    assert_eq!(f.count(-1), c / 2 - i);
                    assert_eq!(f.count(s), c / 2 - i);
                    assert!(f.remove(-1));
                    assert_eq!(f.count(-1), c / 2 - i - 1);
                    assert_eq!(f.count(s), c / 2 - i);
                    assert!(f.remove(s));
                    assert_eq!(f.count(-1), c / 2 - i - 1);
                    assert_eq!(f.count(s), c / 2 - i - 1);
                }
                assert!(f.is_empty());
            }
        }
    }

    #[test]
    fn test_it_works() {
        for fp_rate_arg in [0.01, 0.001, 0.0001] {
            let mut f = Filter::new(100_000, fp_rate_arg);
            assert!(!f.contains(0));
            assert_eq!(f.len(), 0);
            for i in 0..f.capacity() {
                f.insert_duplicated(i).unwrap();
            }
            for i in 0..f.capacity() {
                assert!(f.contains(i));
            }
            let est_fp_rate =
                (0..).take(50_000).filter(|i| f.contains(i)).count() as f64 / 50_000.0;
            dbg!(f.max_error_ratio(), est_fp_rate);
            assert!(est_fp_rate <= f.max_error_ratio());
        }
    }

    #[test]
    fn test_dec_offset_edge_case() {
        // case found in fuzz testing
        #[rustfmt::skip]
        let sample = [(0u16, 287), (2u16, 1), (9u16, 2), (10u16, 1), (53u16, 5), (61u16, 5), (127u16, 2), (232u16, 1), (255u16, 21), (314u16, 2), (317u16, 2), (384u16, 2), (511u16, 3), (512u16, 2), (1599u16, 2), (2303u16, 5), (2559u16, 2), (2568u16, 3), (2815u16, 2), (6400u16, 2), (9211u16, 2), (9728u16, 2), (10790u16, 1), (10794u16, 94), (10797u16, 2), (10999u16, 2), (11007u16, 2), (11520u16, 1), (12800u16, 4), (12842u16, 2), (13823u16, 1), (14984u16, 2), (15617u16, 2), (15871u16, 4), (16128u16, 3), (16383u16, 2), (16394u16, 1), (18167u16, 2), (23807u16, 1), (32759u16, 2) ];
        let mut f = Filter::new(400, 0.1);
        for (i, c) in sample {
            for _ in 0..c {
                f.insert_duplicated(i).unwrap();
            }
        }
        assert_eq!(f.raw_block(2).offset, 3);
        assert_eq!(f.raw_block(3).offset, u8::MAX as u64);
        f.validate_offsets(0, f.total_buckets().get());
        f.remove(0u16);
        assert_eq!(f.raw_block(2).offset, 2);
        assert_eq!(f.raw_block(3).offset, 254);
        f.validate_offsets(0, f.total_buckets().get());
    }
}
