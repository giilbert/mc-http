use crate::utils::unlikely;

/// A vector that supports generational indices with u32 generations and u16 indices.
pub struct U16GenVec<T> {
    items: Vec<(Generation, Option<T>)>,
    free_indices: Vec<usize>,
}

type Index = u16;
type Generation = u32;

/// An indentifier into a [`U16GenVec`].
pub struct GenIdx<T> {
    generation: Generation,
    index: Index,
    _marker: std::marker::PhantomData<T>,
}

impl<T> U16GenVec<T> {
    /// Creates a new, empty [`U16GenVec`].
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            free_indices: Vec::new(),
        }
    }

    /// Inserts a new item into the vector, returning its generational index.
    pub fn insert(&mut self, item: T) -> GenIdx<T> {
        match self.free_indices.pop() {
            Some(free_index) => {
                let (old_generation, _) = self.items[free_index];

                if unlikely(old_generation == u32::MAX) {
                    panic!("generation overflow for index {}", free_index);
                }
                if unlikely(free_index > u16::MAX as usize) {
                    panic!("index {} exceeds maximum u16 value", free_index);
                }

                let new_generation = old_generation + 1;

                self.items[free_index] = (new_generation, Some(item));

                GenIdx {
                    generation: new_generation,
                    index: free_index as u16,
                    _marker: std::marker::PhantomData,
                }
            }
            None => {
                let index = self.items.len();

                if unlikely(index > u16::MAX as usize) {
                    panic!("index {} exceeds maximum u16 value", index);
                }
                self.items.push((0, Some(item)));

                GenIdx {
                    generation: 0,
                    index: index as u16,
                    _marker: std::marker::PhantomData,
                }
            }
        }
    }

    /// Retrieves an item by its generational index.
    ///
    /// If the index is invalid or the generation does not match, `None` is returned.
    pub fn get(&self, gen_idx: &GenIdx<T>) -> Option<&T> {
        let idx = gen_idx.index as usize;
        if idx >= self.items.len() {
            return None;
        }

        let (generation, item_opt) = &self.items[idx];
        if *generation != gen_idx.generation {
            return None;
        }

        item_opt.as_ref()
    }

    /// Removes an item by its generational index.
    pub fn remove(&mut self, gen_idx: &GenIdx<T>) -> Option<T> {
        let idx = gen_idx.index as usize;
        if idx >= self.items.len() {
            return None;
        }

        let (generation, item_opt) = &mut self.items[idx];
        if *generation != gen_idx.generation {
            return None;
        }

        let item = item_opt.take();
        if item.is_some() {
            self.free_indices.push(idx);
        }
        item
    }
}
