use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;
use crate::traits::ScalarField;
use crate::traits::Scheme;

use super::error::TBlsError;
use super::poly::PriShare;
use super::poly::PubPoly;

use std::collections::HashMap;

const INDEX_LEN: usize = 2;

pub fn sign<S: Scheme>(pri_share: &PriShare<S>, msg: &[u8]) -> Result<SigShare<S>, TBlsError> {
    let v = <S::Key as PairingCurve>::bls_sign(msg, &pri_share.v)?;

    Ok(SigShare { i: pri_share.i, v })
}

pub fn verify<S: Scheme>(
    public: &PubPoly<S>,
    msg: &[u8],
    sh: &SigShare<S>,
) -> Result<(), TBlsError> {
    let key = public.eval(sh.i).v;
    <S::Key as PairingCurve>::bls_verify(&key, sh.value(), msg)?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct SigShare<S: Scheme> {
    i: u32,
    v: <S::Sig as Group>::Affine,
}

impl<S: Scheme> SigShare<S> {
    pub fn serialize(&self) -> Result<Vec<u8>, TBlsError> {
        let mut tbls_bytes = (self.i as u16).to_be_bytes().to_vec();
        let mut bls_bytes = self.v.serialize()?;
        tbls_bytes.append(&mut bls_bytes);

        Ok(tbls_bytes)
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, TBlsError> {
        let expected = <S::Sig as Group>::POINT_SIZE + INDEX_LEN;
        if raw.len() != expected {
            return Err(TBlsError::InvalidInputLenght {
                expected,
                received: raw.len(),
            });
        }
        let i = u32::from_be_bytes([0, 0, raw[0], raw[1]]);
        let v = Affine::deserialize(&raw[2..])?;
        Ok(Self { i, v })
    }

    pub fn index(&self) -> u32 {
        self.i
    }

    pub fn value(&self) -> &<S::Sig as Group>::Affine {
        &self.v
    }
}

// Recover reconstructs the full BLS signature S = x * H(m) from a threshold t
// of signature shares Si using Lagrange interpolation.
pub fn recover<S: Scheme>(
    public: &PubPoly<S>,
    msg: &[u8],
    sigs: &[SigShare<S>],
    t: usize,
) -> Result<<S::Sig as Group>::Affine, TBlsError> {
    let mut sorted: Vec<&SigShare<S>> = vec![];

    for sig in sigs {
        if <S::Key as PairingCurve>::bls_verify(public.eval(sig.index()).value(), sig.value(), msg)
            .is_err()
        {
            continue;
        }

        sorted.push(sig);
        if sorted.len() >= t {
            break;
        }
    }
    sorted.sort_by_key(|share| share.index());

    let mut map: HashMap<u32, (S::Scalar, &<S::Sig as Group>::Affine)> = HashMap::new();
    for share in sorted {
        let xi = S::Scalar::from_u64((share.index() + 1).into());
        map.insert(share.index(), (xi, share.value()));
    }

    let mut acc = <S::Sig as Group>::Projective::identity();
    for (i, xi) in &map {
        let mut yi: <S::Sig as Group>::Projective = xi.1.into();
        let mut num = S::Scalar::one();
        let mut den = S::Scalar::one();

        for (j, xj) in &map {
            if i == j {
                continue;
            }
            num *= &xj.0;
            let mut tmp = xj.0;
            tmp -= &xi.0;
            den *= &tmp;
        }

        let inv = den.invert()?;
        num *= &inv;
        yi *= &num;
        acc += &yi;
    }

    Ok(acc.into())
}
