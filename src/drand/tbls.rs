use crate::traits::Affine;
use crate::traits::Group;
use crate::traits::PairingCurve;
use crate::traits::Projective;
use crate::traits::ScalarField;

use super::error::TBlsError;
use super::poly::PriShare;
use super::poly::PubPoly;
use super::scheme::Scheme;

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

#[derive(Debug)]
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
        if S::bls_verify(public.eval(sig.index()).value(), sig.value(), msg).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drand::scheme::DefaultScheme;

    #[test]
    fn test_recover_default() {
        recover_default::<DefaultScheme>();
    }

    fn recover_default<S: Scheme>() {
        let public: PubPoly<S> = PubPoly { commits: vec![
            Affine::deserialize(&hex::decode("981b7605af21a41f044450a032e5087667150dba5bcf0dddfa95577fc5cabeb0c868806d459419ac80dd7719eadc957b").unwrap()).unwrap(),
            Affine::deserialize(&hex::decode("b6be23db8a387de50341d552d05431d0bd7eccdd0e9b8c162166127cc5a6b0c6db660e3f4d28122cb013b9ab14c29471").unwrap()).unwrap()
        ],
    };
        let msg = hex::decode("1259db124468be37bc0d6d3fb7d7d8bb069cbfb4c6bad8f7a1cac775fe71c45d")
            .unwrap();
        let s1=SigShare::deserialize(&hex::decode("0001b5159d30961ed801eb748971ff6a6ce70acb61e76b8ced40322ae977085963670322443ae1dc3e54889befdeaef8766412e1c0c9c2ffc06f929af7bd1a20514ae39cb43f74ee993ec01cb1cc896aeca223a4e510b6fa90b72f4d6b9622973a73").unwrap()).unwrap();
        let s0=SigShare::deserialize(&hex::decode("00008c699f8a94765d743a3adfa507c5978b2c5ae3de611e2f21c943ca3e8a506faf2fac51681f3b8900cfb25469ded00ae90387905d6f1ae71a85109056956d71956971bc5041bb059429868c9c3a0fbd504f6204a7661164b79a7920fa2cba0c9b").unwrap()).unwrap();
        let sigs = vec![s0, s1];
        let t = 2;

        let recovered = recover(&public, &msg, &sigs, t).unwrap();
        let required=Affine::deserialize(&hex::decode("a5ca5628c4c88b33d33f5dce6c0992289e9134eaf3b6e441053ebae4e4a309829982c658fde1f4899a729c8ac37803b90b138ca7e64b5ad53fcf726841b0ef70515f2348d07924af4c430f7a899d2689bb2dab5ef0381e6b2aaea0e4948b215c").unwrap()).unwrap();

        assert_eq!(recovered, required);

        // verify_recovered
        S::bls_verify(&public.commits[0], &recovered, &msg).unwrap();
    }
}
