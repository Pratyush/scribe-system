// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! this file implements the conversion logic for elliptic curve point between
//! - short Weierstrass form
//! - twisted Edwards form
//!
//! Note that the APIs below create no circuits.
//! An entity should either know both the SW and TE form of a
//! point; or know none of the two. There is no need to generate
//! a circuit for arguing secret knowledge of one form while
//! the other form is public. In practice a prover will convert all of the
//! points to the TE form and work on the TE form inside the circuits.

use super::TEPoint;
use ark_ec::short_weierstrass::{Affine as SWAffine, SWCurveConfig as SWParam};
use scribe_streams::serialize::RawPrimeField;

impl<F, P> From<SWAffine<P>> for TEPoint<F>
where
    F: RawPrimeField + SWToTEConParam,
    P: SWParam<BaseField = F>,
{
    fn from(p: SWAffine<P>) -> Self {
        // this function is only correct for BLS12-377
        // (other curves does not impl an SW form)

        // if p is an infinity point
        // return infinity point
        if p.infinity {
            return Self(F::zero(), F::one());
        }

        // we need to firstly convert this point into
        // TE form, and then build the point

        // safe unwrap
        let s = F::from(F::S);
        let neg_alpha = F::from(F::NEG_ALPHA);
        let beta = F::from(F::BETA);

        // we first transform the Weierstrass point (px, py) to Montgomery point (mx,
        // my) where mx = s * (px - alpha)
        // my = s * py
        let montgomery_x = s * (p.x + neg_alpha);
        let montgomery_y = s * p.y;
        // then we transform the Montgomery point (mx, my) to TE point (ex, ey) where
        // ex = beta * mx / my
        // ey = (mx - 1) / (mx + 1)
        let edwards_x = beta * montgomery_x / montgomery_y;
        let edwards_y = (montgomery_x - F::one()) / (montgomery_x + F::one());

        TEPoint(edwards_x, edwards_y)
    }
}

/// This trait holds constants that are used for curve conversion from
/// short Weierstrass form to twisted Edwards form.
pub trait SWToTEConParam: RawPrimeField {
    /// Parameter S.
    const S: Self::BigInt;
    /// Parameter 1/alpha.
    const NEG_ALPHA: Self::BigInt;
    /// Parameter beta.
    const BETA: Self::BigInt;
}
