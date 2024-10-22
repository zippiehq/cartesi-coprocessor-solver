use alloy_primitives::utils::Keccak256;
use alloy_primitives::B256;

pub fn create_proofs(leaves: Vec<B256>, height: usize) -> Result<(B256, Vec<B256>), String> {
    let mut pristine_node = B256::default();

    let mut current_level = leaves.clone();
    let leaf_count = leaves.len() as usize;
    let mut siblings = vec![B256::default(); (leaf_count * height) as usize];

    for level_idx in 0..height {
        for leaf_idx in 0..leaf_count {
            let sibling_idx: usize = (leaf_idx >> level_idx) ^ 1;
            siblings[(leaf_idx * height + level_idx) as usize] =
                *at(&current_level, sibling_idx as usize, &pristine_node);
        }

        current_level = parent_level(&current_level, &pristine_node);
        let mut hasher = Keccak256::new();
        hasher.update(pristine_node.as_slice());
        hasher.update(pristine_node.as_slice());
        pristine_node = B256::from(hasher.finalize());
    }

    if current_level.len() > 1 {
        return Err(format!(
            "too many leaves [{}] for height [{}]",
            leaf_count, height
        ));
    }

    Ok((*at(&current_level, 0, &pristine_node), siblings))
}

fn parent_level(level: &[B256], pristine_node: &B256) -> Vec<B256> {
    let mut new_level = Vec::with_capacity((level.len() + 1) / 2);
    for idx in (0..level.len()).step_by(2) {
        let left_child = &level[idx];
        let right_child = at(level, idx + 1, pristine_node);
        let mut hasher = Keccak256::new();
        hasher.update(left_child.as_slice());
        hasher.update(right_child.as_slice());
        new_level.push(B256::from(hasher.finalize()));
    }
    new_level
}

fn at<'a>(array: &'a [B256], index: usize, default_value: &'a B256) -> &'a B256 {
    if (index as usize) < array.len() {
        &array[index as usize]
    } else {
        default_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex_literal::hex;

    #[test]
    fn test_single_0_leaf_merkle_root() {
        let leaf = B256::from(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        let expected_root = B256::from(hex!(
            "0a162946e56158bac0673e6dd3bdfdc1e4a0e7744a120fdb640050c8d7abe1c6"
        ));
        let height = 63;
        let (root, proofs) = create_proofs(vec![leaf], height).unwrap();
        println!("{:?}", proofs);
        assert_eq!(root, expected_root);
    }
}
