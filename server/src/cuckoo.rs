// concilia uses a sled-backed cuckoo filter to predict whether a claim token has been used before or not
// the filter MAY give a false positive - i.e, saying a claim token has been used when it hasn't
// the filter WILL NOT give a false negative

#[inline]
fn hash<T: ?Sized + std::hash::Hash, H: std::hash::Hasher + Clone>(hasher: &H, item: &T) -> u64 {
    let mut hasher = hasher.clone();
    item.hash(&mut hasher);
    hasher.finish()
}

use ahash::RandomState;
use rand::Rng;
use rkyv::{Archive, Serialize, Deserialize};
use tracing::debug;
use std::hash::{Hash, Hasher, BuildHasher};
use std::marker::PhantomData;

/// Builder for `ScalableCuckooFilter`.
#[derive(Debug)]
pub struct ScalableCuckooFilterBuilder {
    initial_capacity: usize,
    false_positive_probability: f64,
    entries_per_bucket: usize,
    max_kicks: usize,
}
impl ScalableCuckooFilterBuilder {
    /// Makes a new `ScalableCuckooFilterBuilder` instance.
    pub fn new() -> Self {
        ScalableCuckooFilterBuilder {
            initial_capacity: 100_000,
            false_positive_probability: 0.001,
            entries_per_bucket: 4,
            max_kicks: 512,
        }
    }
    
    /// Sets the initial capacity (i.e., the number of estimated maximum items) of this filter.
    ///
    /// The default value is `100_000`.
    #[must_use]
    pub fn capacity_per_filter(mut self, capacity_hint: usize) -> Self {
        self.initial_capacity = capacity_hint;
        self
    }

    /// Sets the expected upper bound of the false positive probability of this filter.
    ///
    /// The default value is `0.001`.
    ///
    /// # Panics
    ///
    /// This method panics if `probability` is not a non-negative number smaller than or equal to `1.0`.
    #[must_use]
    pub fn false_positive_probability(mut self, probability: f64) -> Self {
        assert!(0.0 < probability && probability <= 1.0);
        self.false_positive_probability = probability;
        self
    }

    /// Builds a `ScalableCuckooFilter` instance.
    pub fn finish<T: Hash + ?Sized>(self) -> ScalableCuckooFilter<T> {
        ScalableCuckooFilter {
            capacity_per_filter: self.initial_capacity,
            false_positive_probability: self.false_positive_probability,
            entries_per_bucket: self.entries_per_bucket,
            max_kicks: self.max_kicks,
            filters: Vec::new(),
            _item: PhantomData,
        }
    }
}

/// Scalable Cuckoo Filter.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct PartialScalableCuckooFilter<T: ?Sized> {
    initial_capacity: usize,
    false_positive_probability: f64,
    entries_per_bucket: usize,
    max_kicks: usize,
    _item: PhantomData<T>,
}

/// Scalable Cuckoo Filter.
pub struct ScalableCuckooFilter<T: ?Sized> {
    filters: Vec<CuckooFilter>,
    capacity_per_filter: usize,
    false_positive_probability: f64,
    entries_per_bucket: usize,
    max_kicks: usize,
    _item: PhantomData<T>,
}
impl<'a, T: Hash + ?Sized> ScalableCuckooFilter<T> {
    pub fn from_partial_and_filters(partial: PartialScalableCuckooFilter<T>, filters: Vec<CuckooFilter>) -> Self {
        ScalableCuckooFilter {
            capacity_per_filter: partial.initial_capacity,
            false_positive_probability: partial.false_positive_probability,
            entries_per_bucket: partial.entries_per_bucket,
            max_kicks: partial.max_kicks,
            filters,
            _item: PhantomData,
        }
    }
    
    pub fn to_partial(&self) -> PartialScalableCuckooFilter<T> {
        PartialScalableCuckooFilter {
            initial_capacity: self.capacity_per_filter,
            false_positive_probability: self.false_positive_probability,
            entries_per_bucket: self.entries_per_bucket,
            max_kicks: self.max_kicks,
            _item: PhantomData,
        }
    }
    /// Makes a new `ScalableCuckooFilter` instance.
    ///
    /// This is equivalent to the following expression:
    ///
    /// ```
    /// # use scalable_cuckoo_filter::{ScalableCuckooFilter, ScalableCuckooFilterBuilder};
    /// # let initial_capacity = 10;
    /// # let false_positive_probability = 0.1;
    /// # let _: ScalableCuckooFilter<()> =
    /// ScalableCuckooFilterBuilder::new()
    ///     .initial_capacity(initial_capacity)
    ///     .false_positive_probability(false_positive_probability)
    ///     .finish()
    /// # ;
    /// ```
    pub fn new(capacity_per_filter: usize, false_positive_probability: f64) -> Self {
        ScalableCuckooFilterBuilder::new()
            .capacity_per_filter(capacity_per_filter)
            .false_positive_probability(false_positive_probability)
            .finish()
    }
    
    /// Returns the approximate number of items inserted in this filter.
    pub fn len(&self) -> usize {
        self.filters.iter().map(|f| f.len()).sum()
    }

    /// Returns `true` if this filter contains no items, otherwise `false`.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the capacity (i.e., the upper bound of acceptable items count) of this filter.
    ///
    /// "capacity" is upper bound of the number of items can be inserted into the filter without resizing.
    pub fn capacity(&self) -> usize {
        self.filters.iter().map(|f| f.capacity()).sum()
    }

    /// Returns the number of bits being used for representing this filter.
    pub fn bits(&self) -> u64 {
        self.filters.iter().map(|f| f.bits()).sum()
    }

    /// Returns `true` if this filter may contain `item`, otherwise `false`.
    pub fn contains(&self, item: &T) -> bool {
        let hasher = RandomState::with_seed(0).build_hasher();
        let item_hash = hash(&hasher, item);
        self.filters
            .iter()
            .any(|f| f.contains(&hasher, item_hash))
    }

    /// Inserts `item` into this filter.
    ///
    /// If the current filter becomes full, it will be expanded automatically.
    pub fn insert(&mut self, item: &T) -> Vec<(&CuckooFilter, usize)> {
        let hasher = RandomState::with_seed(0).build_hasher();
        let item_hash = hash(&hasher, item);
        let last = self.filters.len() - 1;
        for filter in self.filters.iter().take(last) {
            if filter.contains(&hasher, item_hash) {
                return vec![];
            }
        }

        self.filters[last].insert(&hasher, &mut rand::thread_rng(), item_hash);
        let mut filters_to_persist = vec![];
        let needs_grow = self.filters[last].is_nearly_full();
        
        if needs_grow {
            debug!("filter[{}] is nearly full", last);
            self.grow();
            let last = self.filters.len() - 1;
            filters_to_persist.push((&self.filters[last-1], last-1));
            filters_to_persist.push((&self.filters[last], last));
        } else {
            filters_to_persist.push((&self.filters[last], last))
        };
        
        filters_to_persist
    }

    /// Shrinks the capacity of this filter as much as possible.
    pub fn shrink_to_fit(&mut self) {
        let hasher = RandomState::with_seed(0).build_hasher();
        for f in &mut self.filters {
            f.shrink_to_fit(&hasher, &mut rand::thread_rng());
        }
    }

    /// Removes `item` from this filter.
    pub fn remove(&mut self, item: &T) {
        let hasher = RandomState::with_seed(0).build_hasher();
        let item_hash = hash(&hasher, item);
        self.filters
            .iter_mut()
            .for_each(|f| f.remove(&hasher, item_hash));
    }

    pub fn grow(&mut self) -> &CuckooFilter {
        let probability =
            self.false_positive_probability / 2f64.powi(self.filters.len() as i32 + 1);
        let fingerprint_bitwidth = ((1.0 / probability).log2()
            + ((2 * self.entries_per_bucket) as f64).log2())
        .ceil() as usize;
        let filter = CuckooFilter::new(
            fingerprint_bitwidth,
            self.entries_per_bucket,
            self.capacity_per_filter,
            self.max_kicks,
        );
        self.filters.push(filter);
        debug!("added another filter with {} spaces", self.capacity_per_filter);
        let last = self.filters.len() - 1;
        &self.filters[last]
    }
}

use std::cmp;
use std::mem;

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct CuckooFilter {
    buckets: Buckets,
    max_kicks: usize,
    exceptional_items: ExceptionalItems,
    item_count: usize,
}
impl CuckooFilter {
    pub fn new(
        fingerprint_bitwidth: usize,
        entries_per_bucket: usize,
        number_of_items_hint: usize,
        max_kicks: usize,
    ) -> Self {
        let number_of_buckets_hint =
            (number_of_items_hint + entries_per_bucket - 1) / entries_per_bucket;
        let buckets = Buckets::new(
            fingerprint_bitwidth,
            entries_per_bucket,
            number_of_buckets_hint,
        );
        CuckooFilter {
            buckets,
            max_kicks,
            exceptional_items: ExceptionalItems::new(),
            item_count: 0,
        }
    }

    #[inline]
    pub fn bits(&self) -> u64 {
        self.buckets.bits() + self.exceptional_items.bits()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.item_count
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buckets.entries() + self.exceptional_items.len()
    }

    #[inline]
    pub fn is_nearly_full(&self) -> bool {
        self.exceptional_items.contains_kicked_out_entries()
    }

    #[inline]
    pub fn contains<H: Hasher + Clone>(&self, hasher: &H, item_hash: u64) -> bool {
        let fingerprint = self.buckets.fingerprint(item_hash);
        let i0 = self.buckets.index(item_hash);
        let i1 = self.buckets.index(i0 as u64 ^ hash(hasher, &fingerprint));
        self.contains_fingerprint(i0, i1, fingerprint)
    }

    #[inline]
    pub fn insert<H: Hasher + Clone, R: Rng>(&mut self, hasher: &H, rng: &mut R, item_hash: u64) {
        let fingerprint = self.buckets.fingerprint(item_hash);
        let i0 = self.buckets.index(item_hash);
        self.insert_fingerprint(hasher, rng, i0, fingerprint);
    }

    #[inline]
    pub fn remove<H: Hasher + Clone>(&mut self, hasher: &H, item_hash: u64) {
        let fingerprint = self.buckets.fingerprint(item_hash);
        let i0 = self.buckets.index(item_hash);
        let i1 = self.buckets.index(i0 as u64 ^ hash(hasher, &fingerprint));

        let removed = if self.exceptional_items.contains(i0, i1, fingerprint) {
            self.exceptional_items.remove(i0, i1, fingerprint)
        } else if self.buckets.contains(i0, fingerprint) {
            self.buckets.remove_fingerprint(i0, fingerprint)
        } else if self.buckets.contains(i1, fingerprint) {
            self.buckets.remove_fingerprint(i1, fingerprint)
        } else {
            false
        };

        if removed {
            self.item_count -= 1;
        }
    }

    #[inline]
    pub fn shrink_to_fit<H: Hasher + Clone, R: Rng>(&mut self, hasher: &H, rng: &mut R) {
        let entries_per_bucket = self.buckets.entries_per_bucket();
        let shrunk_buckets_len = Buckets::required_number_of_buckets(
            (self.item_count + entries_per_bucket - 1) / entries_per_bucket,
        );
        if shrunk_buckets_len < self.buckets.len() {
            let mut shrunk_filter = CuckooFilter::new(
                self.buckets.fingerprint_bitwidth(),
                self.buckets.entries_per_bucket(),
                self.item_count,
                self.max_kicks,
            );
            for (i, fingerprint) in self.buckets.iter() {
                let shrunk_i = shrunk_filter.buckets.index(i as u64);
                shrunk_filter.insert_fingerprint(hasher, rng, shrunk_i, fingerprint);
            }
            *self = shrunk_filter;
        }
        self.exceptional_items.shrink_to_fit();
    }

    #[inline]
    fn contains_fingerprint(&self, i0: usize, i1: usize, fingerprint: u64) -> bool {
        if self.exceptional_items.contains(i0, i1, fingerprint) {
            true
        } else if fingerprint == 0 {
            false
        } else {
            self.buckets.contains(i0, fingerprint) || self.buckets.contains(i1, fingerprint)
        }
    }

    #[inline]
    fn insert_fingerprint<H: Hasher + Clone, R: Rng>(
        &mut self,
        hasher: &H,
        rng: &mut R,
        i0: usize,
        fingerprint: u64,
    ) {
        let i1 = self.buckets.index(i0 as u64 ^ hash(hasher, &fingerprint));
        if self.contains_fingerprint(i0, i1, fingerprint) {
            return;
        }
        self.item_count += 1;

        if fingerprint == 0 {
            self.exceptional_items.insert(i0, i1, 0);
            return;
        }
        if self.buckets.try_insert(i0, fingerprint) || self.buckets.try_insert(i1, fingerprint) {
            return;
        }

        let mut fingerprint = fingerprint;
        let mut i = if rng.gen::<bool>() { i0 } else { i1 };
        let mut prev_i = i;
        for _ in 0..self.max_kicks {
            fingerprint = self.buckets.random_swap(rng, i, fingerprint);
            prev_i = i;
            i = self.buckets.index(i as u64 ^ hash(hasher, &fingerprint));
            if self.buckets.try_insert(i, fingerprint) {
                return;
            }
        }
        self.exceptional_items.insert(prev_i, i, fingerprint);
    }
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct ExceptionalItems(Vec<(u64, usize)>);
impl ExceptionalItems {
    fn new() -> Self {
        ExceptionalItems(Vec::new())
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn bits(&self) -> u64 {
        (mem::size_of::<(u64, usize)>() * self.0.capacity()) as u64 * 8
    }

    #[inline]
    fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit();
    }

    #[inline]
    fn contains_kicked_out_entries(&self) -> bool {
        self.0
            .last()
            .map_or(false, |&(fingerprint, _)| fingerprint != 0)
    }

    #[inline]
    fn contains(&self, i0: usize, i1: usize, fingerprint: u64) -> bool {
        let item = (fingerprint, cmp::min(i0, i1));
        self.0.binary_search(&item).is_ok()
    }

    #[inline]
    fn insert(&mut self, i0: usize, i1: usize, fingerprint: u64) {
        let item = (fingerprint, cmp::min(i0, i1));
        for i in 0..self.0.len() {
            debug_assert_ne!(self.0[i], item);
            if item < self.0[i] {
                self.0.insert(i, item);
                return;
            }
        }
        self.0.push(item);
    }

    #[inline]
    fn remove(&mut self, i0: usize, i1: usize, fingerprint: u64) -> bool {
        let item = (fingerprint, cmp::min(i0, i1));
        if let Ok(index) = self.0.binary_search(&item) {
            self.0.remove(index);
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct Buckets {
    fingerprint_bitwidth: usize, // fingerprint length in bits
    entries_per_bucket: usize,   // number of entries per bucket
    bucket_bitwidth: usize,
    bucket_index_bitwidth: usize,
    bytes: Vec<u8>
}
impl Buckets {
    pub fn new(
        fingerprint_bitwidth: usize,
        entries_per_bucket: usize,
        number_of_buckets_hint: usize,
    ) -> Self {
        let bucket_index_bitwidth =
            number_of_buckets_hint.next_power_of_two().trailing_zeros() as usize;
        let bucket_bitwidth = fingerprint_bitwidth * entries_per_bucket;
        Buckets {
            fingerprint_bitwidth,
            entries_per_bucket,
            bucket_bitwidth,
            bucket_index_bitwidth,
            bytes: vec![0; (bucket_bitwidth << bucket_index_bitwidth + 7) / 8],
        }
    }

    #[inline]
    pub fn required_number_of_buckets(number_of_buckets_hint: usize) -> usize {
        number_of_buckets_hint.next_power_of_two()
    }

    #[inline]
    pub fn len(&self) -> usize {
        1 << self.bucket_index_bitwidth
    }

    #[inline]
    pub fn entries(&self) -> usize {
        self.len() * self.entries_per_bucket
    }

    #[inline]
    pub fn bits(&self) -> u64 {
        (self.bytes.len() * 8) as u64
    }

    #[inline]
    pub fn index(&self, hash: u64) -> usize {
        (hash & ((1 << self.bucket_index_bitwidth) - 1)) as usize
    }

    #[inline]
    pub fn fingerprint(&self, hash: u64) -> u64 {
        hash >> (64 - self.fingerprint_bitwidth)
    }

    #[inline]
    pub fn entries_per_bucket(&self) -> usize {
        self.entries_per_bucket
    }

    #[inline]
    pub fn fingerprint_bitwidth(&self) -> usize {
        self.fingerprint_bitwidth
    }

    #[inline]
    pub fn iter(&self) -> Iter {
        Iter::new(self)
    }

    #[inline]
    pub fn contains(&self, bucket_index: usize, fingerprint: u64) -> bool {
        debug_assert_ne!(fingerprint, 0);
        for i in 0..self.entries_per_bucket {
            let f = self.get_fingerprint(bucket_index, i);
            if f == fingerprint {
                return true;
            } else if f == 0 {
                break;
            }
        }
        false
    }

    #[inline]
    pub fn try_insert(&mut self, bucket_index: usize, fingerprint: u64) -> bool {
        debug_assert_ne!(fingerprint, 0);
        for i in 0..self.entries_per_bucket {
            let f = self.get_fingerprint(bucket_index, i);
            if f == 0 {
                self.set_fingerprint(bucket_index, i, fingerprint);
                return true;
            }
            debug_assert_ne!(f, fingerprint);
        }
        false
    }

    #[inline]
    pub fn random_swap<R: Rng>(
        &mut self,
        rng: &mut R,
        bucket_index: usize,
        fingerprint: u64,
    ) -> u64 {
        let i = rng.gen_range(0..self.entries_per_bucket);
        let f = self.get_fingerprint(bucket_index, i);
        self.set_fingerprint(bucket_index, i, fingerprint);

        debug_assert_ne!(fingerprint, 0);
        debug_assert_eq!(fingerprint, self.get_fingerprint(bucket_index, i));
        debug_assert_ne!(f, fingerprint);
        debug_assert_ne!(f, 0);
        f
    }

    #[inline]
    pub fn remove_fingerprint(&mut self, bucket_index: usize, fingerprint: u64) -> bool {
        if fingerprint == 0 {
            println!("Fingerprint zero");
            return false;
        }
        for i in 0..self.entries_per_bucket {
            let f = self.get_fingerprint(bucket_index, i);
            if f == fingerprint {
                self.set_fingerprint(bucket_index, i, 0);
                return true;
            }
        }
        false
    }

    #[inline]
    fn set_fingerprint(&mut self, bucket_index: usize, entry_index: usize, fingerprint: u64) {
        let offset = self.bucket_bitwidth * bucket_index + self.fingerprint_bitwidth * entry_index;
        self.set_uint(offset, self.fingerprint_bitwidth, fingerprint);
    }

    #[inline]
    fn get_fingerprint(&self, bucket_index: usize, entry_index: usize) -> u64 {
        let offset = self.bucket_bitwidth * bucket_index + self.fingerprint_bitwidth * entry_index;
        self.get_uint(offset, self.fingerprint_bitwidth)
    }

    #[inline]
    pub fn get_uint(&self, position: usize, size: usize) -> u64 {
        let mut value = 0;
        let start = position / 8;
        let end = (position + size + 7) / 8;
        for (i, &b) in self.bytes[start..end].iter().enumerate() {
            value |= u64::from(b) << (i * 8);
        }

        let offset = position % 8;
        let mask = (1 << size) - 1;
        (value >> offset) & mask
    }

    #[inline]
    pub fn set_uint(&mut self, position: usize, mut size: usize, mut value: u64) {
        let mut offset = position % 8;
        for b in &mut self.bytes[position / 8..] {
            let high = ((u64::from(*b) >> size) << size) as u8;
            let middle = (value << offset) as u8;
            let low = *b & ((1 << offset) - 1);
            *b = high | middle | low;

            let drop_bits = 8 - offset;
            if size <= drop_bits {
                break;
            }
            size -= drop_bits;
            value >>= drop_bits;
            offset = 0;
        }
    }
}

#[derive(Debug)]
pub struct Iter<'a> {
    buckets: &'a Buckets,
    bucket_i: usize,
    entry_i: usize,
}
impl<'a> Iter<'a> {
    fn new(buckets: &'a Buckets) -> Self {
        Iter {
            buckets,
            bucket_i: 0,
            entry_i: 0,
        }
    }
}
impl<'a> Iterator for Iter<'a> {
    type Item = (usize, u64);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.bucket_i == self.buckets.len() {
                return None;
            } else if self.entry_i == self.buckets.entries_per_bucket {
                self.bucket_i += 1;
                self.entry_i = 0;
            } else {
                let f = self.buckets.get_fingerprint(self.bucket_i, self.entry_i);
                if f == 0 {
                    self.bucket_i += 1;
                    self.entry_i = 0;
                } else {
                    self.entry_i += 1;
                    return Some((self.bucket_i, f));
                }
            }
        }
    }
}
