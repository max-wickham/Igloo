// Copyright (c) 2025 Max Wickham
// SPDX-License-Identifier: MIT
// See the MIT License for details: https://opensource.org/licenses/MIT

use alloy::primitives::Uint;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::PrimeField;
use k256::AffinePoint;
use k256::{
    ProjectivePoint,
    Scalar,
    elliptic_curve::sec1::ToEncodedPoint,
};

use crate::contract::IIgloo;

lazy_static::lazy_static! {
    // The order of the secp256k1 curve
    pub static ref Q : Uint<256, 4> = Uint::<256, 4>::from_limbs([
        0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff
    ]);
}

pub fn scalar_to_point(scalar: Scalar) -> ProjectivePoint {
    let generator = ProjectivePoint::GENERATOR;
    generator * scalar
}

pub fn affine_to_point(point: AffinePoint) -> IIgloo::Point {
    let point = point.to_encoded_point(false);
    let x = Uint::<256, 4>::try_from_be_slice(point.x().unwrap());
    let y = Uint::<256, 4>::try_from_be_slice(point.y().unwrap());

    IIgloo::Point {
        x: x.unwrap(),
        y: y.unwrap(),
    }
}

pub fn point_to_projective(point: IIgloo::Point) -> ProjectivePoint {
    let x_field_bytes = k256::FieldBytes::from(point.x.to_be_bytes());
    let y_field_bytes = k256::FieldBytes::from(point.y.to_be_bytes());

    let encoded_point = k256::EncodedPoint::from_affine_coordinates(
        &x_field_bytes,
        &y_field_bytes,
        false // uncompressed
    );
    let point = AffinePoint::from_encoded_point(&encoded_point);
    let point = point.expect("Failed to convert point to affine");
    
    ProjectivePoint::from(point)
}

pub fn uint_to_scalar(uint: Uint<256, 4>) -> Scalar {
    // let mut bytes = [0u8; 32];
    let bytes = uint.to_be_bytes();
    let scalar = Scalar::from_repr(bytes.into());
    scalar.expect("Failed to convert uint to scalar")
}

pub fn scalar_to_uint(scalar: Scalar) -> Uint<256, 4> {
    let bytes = scalar.to_bytes();
    
    Uint::<256, 4>::from_be_bytes(bytes.into())
}

pub fn u64_to_uint(x: u64) -> Uint<256, 4> {
    Uint::<256, 4>::from(x)
}