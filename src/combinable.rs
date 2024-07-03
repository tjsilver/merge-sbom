use std::collections::HashSet;
use std::iter::Extend;
use std::hash::Hash;
pub trait Combinable {
    fn combine(self, b: Self) -> Self;
}

impl Combinable for String {
    fn combine(self, b: Self) -> Self {
        if self == b {
            return self;
        }
        format!("{} AND {}", self, b)
    }
}

impl<T> Combinable for HashSet<T> where T: Clone + Eq + Hash {
    fn combine(self, b: Self) -> Self {
        let mut merged_hashset = self;
        merged_hashset.extend(b);

        merged_hashset
    }
}

impl<T:Combinable> Combinable for Option<T> {
    fn combine(self, b: Self) -> Self {
        match(self, b) {
            (None, None) => None,
            (None, b @Some(_)) => b,
            (a @Some(_), None) => a,
            (Some(a), Some(b)) => Some(T::combine(a, b)),
        }    
    }
}