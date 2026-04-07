use ark_bn254::{Fr, G1Affine};
use rand::Rng;

use crate::crypto::hash::{hash_elements, hash_point};
use crate::crypto::pedersen::{batch_pedersen_commit_blinded, CommitKey};
use crate::crypto::CryptoError;

fn expected_leaf_count(depth: usize) -> Option<usize> {
    1usize.checked_shl(depth as u32)
}

fn build_base_merkle_tree(leaves: &[Fr], depth: usize) -> Result<(Vec<Vec<Fr>>, Fr), CryptoError> {
    let expected = expected_leaf_count(depth).ok_or(CryptoError::InvalidDepth)?;
    if leaves.len() != expected || leaves.is_empty() {
        return Err(CryptoError::InvalidInputLength(
            "leaf count must be exactly 2^depth",
        ));
    }

    let mut tree = Vec::with_capacity(depth + 1);
    tree.push(leaves.to_vec());
    for level in 0..depth {
        let prev = &tree[level];
        let next = (0..prev.len() / 2)
            .map(|i| hash_elements(&[prev[2 * i], prev[2 * i + 1]]))
            .collect::<Vec<_>>();
        tree.push(next);
    }
    Ok((tree.clone(), tree[depth][0]))
}

pub fn build_merkle_tree_from_field_elements(
    leaves: &[Fr],
    depth: usize,
) -> Result<(Vec<Vec<Fr>>, Fr), CryptoError> {
    build_base_merkle_tree(leaves, depth)
}

pub fn build_merkle_tree_from_group_elements(
    leaves: &[G1Affine],
    depth: usize,
) -> Result<(Vec<Vec<Fr>>, Fr), CryptoError> {
    let hashed = leaves.iter().map(hash_point).collect::<Vec<_>>();
    build_base_merkle_tree(&hashed, depth)
}

pub fn get_merkle_proof(
    tree: &[Vec<Fr>],
    idx: usize,
    depth: usize,
) -> Result<Vec<Fr>, CryptoError> {
    if tree.len() <= depth || tree[0].is_empty() || idx >= tree[0].len() {
        return Err(CryptoError::InvalidInputLength("invalid tree or index"));
    }

    let mut proof = Vec::with_capacity(depth);
    let mut cur = idx;
    for level in 0..depth {
        let sibling = cur ^ 1;
        if sibling >= tree[level].len() {
            return Err(CryptoError::InvalidInputLength("malformed tree"));
        }
        proof.push(tree[level][sibling]);
        cur /= 2;
    }
    Ok(proof)
}

pub fn verify_membership(root: Fr, commitment: &G1Affine, proof: &[Fr], idx: usize) -> bool {
    let mut cur_hash = hash_point(commitment);
    let mut cur_idx = idx;
    for sibling in proof {
        cur_hash = if cur_idx % 2 == 0 {
            hash_elements(&[cur_hash, *sibling])
        } else {
            hash_elements(&[*sibling, cur_hash])
        };
        cur_idx /= 2;
    }
    cur_hash == root
}

pub type CommitMatrixOutput = (Vec<Vec<Fr>>, Fr, Vec<G1Affine>, Vec<Fr>);

pub fn commit_matrix<R: Rng>(
    columns: &[Vec<Fr>],
    ck: &CommitKey,
    depth: usize,
    rng: &mut R,
) -> Result<CommitMatrixOutput, CryptoError> {
    let (commitments, blindings) = batch_pedersen_commit_blinded(columns, ck, rng)?;
    let (tree, root) = build_merkle_tree_from_group_elements(&commitments, depth)?;
    Ok((tree, root, commitments, blindings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::setup_commit_key;

    #[test]
    fn test_merkle_membership_from_commitment() {
        let mut rng = ark_std::test_rng();
        let ck = setup_commit_key(2, &mut rng);
        let columns = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
            vec![Fr::from(5u64), Fr::from(6u64)],
            vec![Fr::from(7u64), Fr::from(8u64)],
        ];
        let (tree, root, commitments, _) = commit_matrix(&columns, &ck, 2, &mut rng).unwrap();
        let idx = 2usize;
        let proof = get_merkle_proof(&tree, idx, 2).unwrap();
        assert!(verify_membership(root, &commitments[idx], &proof, idx));
    }
}
