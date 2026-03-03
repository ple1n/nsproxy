pub trait CRDT: Sized {
    fn merge(self, other: Self) -> Self;
}
