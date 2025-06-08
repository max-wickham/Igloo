// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// import {console2 as console} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";

import {Secp256k1 as LibSecp256k1, PublicKey} from "crysol/Secp256k1.sol";
import {
    Point,
    ProjectivePoint,
    Points as PointsLib
} from "crysol/arithmetic/Points.sol";
import {Felt, Fp} from "crysol/arithmetic/Fp.sol";

import {Igloo} from "../src/Igloo.sol";
import {IIgloo} from "../src/IIgloo.sol";
import {IglooProxyFactory} from "../src/IglooProxyFactory.sol";
import {IglooProxy} from "../src/IglooProxy.sol";

contract TestIIgloo is Test {
    using LibSecp256k1 for PublicKey;
    using PointsLib for Point;
    using PointsLib for ProjectivePoint;
    using Fp for Felt;

    /// @dev The order of the secp256k1 curve.
    uint constant Q =
        115792089237316195423570985008687907852837564279074904382605163141518161494337;

    // -- Events (Copied from IIgloo) --
    event SharedCommitment(
        address indexed sender,
        Point[] commitment,
        IIgloo.Sigma sigma,
        Point channelKey
    );

    event CommitmentsShared(PublicKey publicKey);

    event SharedFunctionOutputs(
        address indexed participant,
        IIgloo.FunctionOutput[] encryptedFunctionOutputs
    );

    event FunctionOutputsShared();

    event ValidatedFunctionOutputs(address indexed participant);

    event FunctionOutputsValidated();

    event FailedKeyGeneration(address sender);

    event DeprecatedKey(address sender);

    IglooProxyFactory factory;
    Igloo singleton;

    function setUp() public {
        factory = new IglooProxyFactory();
        singleton = new Igloo();
    }

    function newIglooProxy(address[] memory participants, uint threshold)
        public
        returns (IIgloo)
    {
        address proxy = factory.createProxy(
            address(singleton),
            participants,
            threshold,
            keccak256(abi.encodePacked("Igloo"))
        );
        return IIgloo(proxy);
    }

    // -- Init --

    function test_deployFactory() public {
        factory = new IglooProxyFactory();
    }

    function test_deploySingleton() public {
        new Igloo();
    }

    function test_init() public {
        uint threshold = 10;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        assertEq(
            igloo.participants(),
            participants,
            "Participants do not match"
        );
        assertEq(igloo.threshold(), threshold, "Threshold does not match");
    }

    function test_init_RevertsIf_ThresholdIsZero() public {
        uint threshold = 0;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        vm.expectRevert();
        newIglooProxy(participants, threshold);
    }

    function test_init_RevertsIf_ThresholdGreaterThanNumParticipants() public {
        uint threshold = 21;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        vm.expectRevert();
        newIglooProxy(participants, threshold);
    }

    /// @dev This test is not strictly necessary, but it is a good sanity check.
    ///      The previous tests already assert this is the case.
    function test_constructor_RevertsIf_NumParticipantsIsZero() public {
        uint threshold = 10;
        uint numParticipants = 0;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        vm.expectRevert();
        newIglooProxy(participants, threshold);
    }

    // -- Share Commitments --

    function test_shareCommitments() public {
        Point memory G = LibSecp256k1.G().intoPoint();

        uint threshold = 10;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            // Create coefficients
            uint[] memory coefficients =
                _randCoefficients(participants[i], threshold, seed);
            Point[] memory commitments = _commitments(coefficients);

            // // Create sigma proof
            uint k = uint(keccak256(abi.encodePacked("k", participants[i]))) % Q;
            Point memory R = _mapToCurve(k);
            uint challenge = igloo.participantChallenge(
                participants[i], commitments[0], R
            );
            // mu = k + a_0 * c,

            uint mu;
            mu = mulmod(coefficients[0], challenge, Q);
            mu = addmod(k, mu, Q);

            // Create channel
            uint a = uint(keccak256(abi.encodePacked("a", participants[i])));
            Point memory channelKey = _mapToCurve(a);

            assert(commitments[0].eq(_mapToCurve(coefficients[0])));
            IIgloo.Sigma memory sigma = IIgloo.Sigma(R, mu);
            assertTrue(
                sigma.R.toProjectivePoint().add(
                    commitments[0].toProjectivePoint().mul(challenge)
                ).toPoint().eq(G.toProjectivePoint().mul(sigma.mu).toPoint())
            );

            // Share the commitments
            vm.prank(participants[i]);
            igloo.shareCommitments(i, commitments, sigma, channelKey);
        }
    }

    function test_shareCommitments_FailsIf_InvalidSigma() public {
        uint threshold = 10;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            // Create coefficients
            uint[] memory coefficients =
                _randCoefficients(participants[i], threshold, seed);
            Point[] memory commitments = _commitments(coefficients);

            // Create faulty sigma proof
            uint k = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory r = _mapToCurve(k);
            uint mu = uint(keccak256(abi.encodePacked("mu", participants[i])));

            // Create channel
            uint a = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory channelKey = _mapToCurve(a);

            // Share the commitments
            vm.prank(participants[i]);
            vm.expectRevert();
            igloo.shareCommitments(
                i, commitments, IIgloo.Sigma(r, mu), channelKey
            );
        }
    }

    function testFuzz_shareCommitments_FailsIf_IncorrectNumberOfCommitments(
        uint offsetFromThreshold
    ) public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        uint numCoefficients = _bound(offsetFromThreshold, 1, 2 * threshold);
        vm.assume(numCoefficients != threshold);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            // Create coefficients
            uint[] memory coefficients =
                _randCoefficients(participants[i], numCoefficients, seed);
            Point[] memory commitments = _commitments(coefficients);

            // Create sigma proof
            uint k = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory r = _mapToCurve(k);
            uint challenge = igloo.participantChallenge(
                participants[i], commitments[0], r
            );
            // // mu = k + a_0 * c
            uint mu = (addmod(k, mulmod(challenge, coefficients[0], Q), Q));

            // Create channel
            uint a = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory channelKey = _mapToCurve(a);

            // Share the commitments
            vm.prank(participants[i]);
            vm.expectRevert();
            igloo.shareCommitments(
                i, commitments, IIgloo.Sigma(r, mu), channelKey
            );
        }
    }

    function test_shareCommitments_ComputesPublicKeyAfterFinalSubmission()
        public
    {
        uint threshold = 10;
        uint numParticipants = 20;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        ProjectivePoint memory publicKeyProjectivePoint =
            PointsLib.ProjectiveIdentity();
        for (uint i; i < participants.length; i++) {
            // Check the current public key is 0,0
            PublicKey memory currentPubKey = igloo.publicKey();
            assert(currentPubKey.x.asUint() == 0);

            // Create coefficients
            uint[] memory coefficients =
                _randCoefficients(participants[i], threshold, seed);
            Point[] memory commitments = _commitments(coefficients);

            publicKeyProjectivePoint =
                publicKeyProjectivePoint.add(commitments[0].toProjectivePoint());

            // // Create sigma proof
            uint k = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory r = _mapToCurve(k);
            uint challenge = igloo.participantChallenge(
                participants[i], commitments[0], r
            );
            // mu = k + a_0 * c
            uint mu = (addmod(k, mulmod(challenge, coefficients[0], Q), Q));

            // Create channel
            uint a = uint(keccak256(abi.encodePacked("a", participants[i])));
            Point memory channelKey = _mapToCurve(a);

            // Share the commitments
            vm.prank(participants[i]);
            igloo.shareCommitments(
                i, commitments, IIgloo.Sigma(r, mu), channelKey
            );

            // TEST submitting again fails
        }

        assert(
            publicKeyProjectivePoint.toPoint().eq(
                igloo.publicKey().intoPoint()
            )
        );
    }

    // TODO reverts if wrong state

    // -- Share Function Outputs --

    function test_shareFunctionOutputs() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );
    }

    function test_shareFunctionOutputs_FailsIf_InvalidNumberOfFunctionOutputs()
        public
    {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        // Create a list of Igloo.FunctionOutput with the wrong number of function outputs
        IIgloo.FunctionOutput[] memory eFunctionOutputs =
            new IIgloo.FunctionOutput[](participants.length - 1);
        vm.prank(participants[0]);
        vm.expectRevert("len(outputs) != len(participants)");
        igloo.shareFunctionOutputs(0, eFunctionOutputs);
    }

    // TODO reverts if in wrong state

    // -- Validate Function Outputs --

    function test_validateFunctionOutputs() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        _performRound3(
            participants, igloo, threshold, seed, functionOutputs
        );
    }

    // TODO test reverts if not in right participant state

    // -- Key Failure and Deprecation --

    function test_failKeyGeneration_SucceedsIf_Round1() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.ROUND_1),
            "Global state is not ROUND_1"
        );

        vm.prank(participants[0]);
        vm.expectEmit();
        emit FailedKeyGeneration(participants[0]);
        igloo.failKeyGeneration(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.FAILED),
            "Global state is not FAILED"
        );
    }

    function test_failKeyGeneration_SucceedsIf_Round2() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.ROUND_2),
            "Global state is not ROUND_2"
        );

        vm.prank(participants[0]);
        vm.expectEmit();
        emit FailedKeyGeneration(participants[0]);
        igloo.failKeyGeneration(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.FAILED),
            "Global state is not FAILED"
        );
    }

    function test_failKeyGeneration_SucceedsIf_Round3() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.ROUND_3),
            "Global state is not ROUND_3"
        );

        vm.prank(participants[0]);
        vm.expectEmit();
        emit FailedKeyGeneration(participants[0]);
        igloo.failKeyGeneration(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.FAILED),
            "Global state is not FAILED"
        );
    }

    function test_failKeyGeneration_RevertIf_Active() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        _performRound3(
            participants, igloo, threshold, seed, functionOutputs
        );

        vm.prank(participants[0]);
        vm.expectRevert("state == ACTIVE");
        igloo.failKeyGeneration(0);
    }

    function test_failKeyGeneration_RevertsIf_Failed() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);
        vm.prank(participants[0]);
        igloo.failKeyGeneration(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.FAILED),
            "Global state is not FAILED"
        );

        vm.prank(participants[0]);
        vm.expectRevert("state == FAILED");
        igloo.failKeyGeneration(0);
    }

    function test_failKeyGeneration_RevertsIf_Deprecated() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        _performRound3(
            participants, igloo, threshold, seed, functionOutputs
        );

        vm.prank(participants[0]);
        igloo.deprecateKey(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.DEPRECATED),
            "Global state is not DEPRECATED"
        );

        vm.prank(participants[0]);
        vm.expectRevert("state == DEPRECATED");
        igloo.failKeyGeneration(0);
    }

    function test_deprecateKey_RevertsIf_NotActive() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        vm.prank(participants[0]);
        vm.expectRevert("state != ACTIVE");
        igloo.deprecateKey(0);

        _performRound1(participants, igloo, threshold, seed);

        vm.prank(participants[0]);
        vm.expectRevert("state != ACTIVE");
        igloo.deprecateKey(0);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        vm.prank(participants[0]);
        vm.expectRevert("state != ACTIVE");
        igloo.deprecateKey(0);

        vm.prank(participants[0]);
        igloo.failKeyGeneration(0);

        vm.prank(participants[0]);
        vm.expectRevert("state != ACTIVE");
        igloo.deprecateKey(0);
    }

    function test_deprecateKey_SucceedsIf_Active() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        _performRound3(
            participants, igloo, threshold, seed, functionOutputs
        );

        vm.prank(participants[0]);
        igloo.deprecateKey(0);

        // Check the global state is correct
        assertEq(
            uint(igloo.state()),
            uint(IIgloo.SessionState.DEPRECATED),
            "Global state is not DEPRECATED"
        );
    }

    // -- Index Auth --

    function test_shareCommitments_participantIndexAuth() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        Point[] memory commitments = new Point[](threshold);
        IIgloo.Sigma memory sigma;
        Point memory channelKey;

        for (uint i; i < participants.length; i++) {
            for (uint j; j < participants.length; j++) {
                if (i != j) {
                    // Perform with a participant
                    vm.prank(participants[i]);
                    vm.expectRevert(
                        abi.encodeWithSelector(
                            IIgloo.InvalidParticipantIndex.selector,
                            j,
                            participants[j],
                            participants[i]
                        )
                    );
                    igloo.shareCommitments(
                        j, commitments, sigma, channelKey
                    );
                }
            }
            // Do once with a random address.
            vm.prank(address(0xbeef));
            vm.expectRevert(
                abi.encodeWithSelector(
                    IIgloo.InvalidParticipantIndex.selector,
                    i,
                    participants[i],
                    address(0xbeef)
                )
            );
            igloo.shareCommitments(i, commitments, sigma, channelKey);
        }
    }

    function test_shareFunctionOutputs_participantIndexAuth() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        IIgloo.FunctionOutput[] memory functionOutputs =
            new IIgloo.FunctionOutput[](participants.length);

        for (uint i; i < participants.length; i++) {
            for (uint j; j < participants.length; j++) {
                if (i != j) {
                    // Perform with a participant
                    vm.prank(participants[i]);
                    vm.expectRevert(
                        abi.encodeWithSelector(
                            IIgloo.InvalidParticipantIndex.selector,
                            j,
                            participants[j],
                            participants[i]
                        )
                    );
                    igloo.shareFunctionOutputs(j, functionOutputs);
                }
            }
            // Do once with a random address.
            vm.prank(address(0xbeef));
            vm.expectRevert(
                abi.encodeWithSelector(
                    IIgloo.InvalidParticipantIndex.selector,
                    i,
                    participants[i],
                    address(0xbeef)
                )
            );
            igloo.shareFunctionOutputs(i, functionOutputs);
        }
    }

    function test_validateFunctionOutputs_participantIndexAuth() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            for (uint j; j < participants.length; j++) {
                if (i != j) {
                    // Perform with a participant
                    vm.prank(participants[i]);
                    vm.expectRevert(
                        abi.encodeWithSelector(
                            IIgloo.InvalidParticipantIndex.selector,
                            j,
                            participants[j],
                            participants[i]
                        )
                    );
                    igloo.validateFunctionOutputs(j);
                }
            }
            // Do once with a random address.
            vm.prank(address(0xbeef));
            vm.expectRevert(
                abi.encodeWithSelector(
                    IIgloo.InvalidParticipantIndex.selector,
                    i,
                    participants[i],
                    address(0xbeef)
                )
            );
            igloo.validateFunctionOutputs(i);
        }
    }

    function test_deprecate_participantIndexAuth() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            for (uint j; j < participants.length; j++) {
                if (i != j) {
                    // Perform with a participant
                    vm.prank(participants[i]);
                    vm.expectRevert(
                        abi.encodeWithSelector(
                            IIgloo.InvalidParticipantIndex.selector,
                            j,
                            participants[j],
                            participants[i]
                        )
                    );
                    igloo.deprecateKey(j);
                }
            }
            // Do once with a random address.
            vm.prank(address(0xbeef));
            vm.expectRevert(
                abi.encodeWithSelector(
                    IIgloo.InvalidParticipantIndex.selector,
                    i,
                    participants[i],
                    address(0xbeef)
                )
            );
            igloo.deprecateKey(i);
        }
    }

    function test_failKeyGeneration_participantIndexAuth() public {
        uint threshold = 5;
        uint numParticipants = 10;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        for (uint i; i < participants.length; i++) {
            for (uint j; j < participants.length; j++) {
                if (i != j) {
                    // Perform with a participant
                    vm.prank(participants[i]);
                    vm.expectRevert(
                        abi.encodeWithSelector(
                            IIgloo.InvalidParticipantIndex.selector,
                            j,
                            participants[j],
                            participants[i]
                        )
                    );
                    igloo.failKeyGeneration(j);
                }
            }
            // Do once with a random address.
            vm.prank(address(0xbeef));
            vm.expectRevert(
                abi.encodeWithSelector(
                    IIgloo.InvalidParticipantIndex.selector,
                    i,
                    participants[i],
                    address(0xbeef)
                )
            );
            igloo.failKeyGeneration(i);
        }
    }

    // -- Signature Generation --

    function test_ableToGenerateSignature() public {
        uint threshold = 3;
        uint numParticipants = 5;
        bytes32 seed = bytes32(0);

        address[] memory participants = _randParticipants(numParticipants, seed);

        IIgloo igloo = newIglooProxy(participants, threshold);

        _performRound1(participants, igloo, threshold, seed);

        uint[][] memory functionOutputs =
            _computeFunctionOutput(participants, threshold, seed);

        _performRound2(
            participants, igloo, threshold, seed, functionOutputs
        );

        _performRound3(
            participants, igloo, threshold, seed, functionOutputs
        );

        // Sign a message and check creates valid schnorr sig

        uint[] memory indices = new uint[](threshold);
        for (uint i; i < threshold; i++) {
            indices[i] = igloo.index(participants[i]);
        }

        // Create nonces
        uint message = uint(keccak256(abi.encodePacked("message")));
        uint[] memory nonceDs = new uint[](threshold);
        uint[] memory nonceEs = new uint[](threshold);
        for (uint i; i < threshold; i++) {
            uint e = uint(keccak256(abi.encodePacked("e", i)));
            uint d = uint(keccak256(abi.encodePacked("e", i)));
            nonceDs[i] = d;
            nonceEs[i] = e;
        }
        uint B = uint(keccak256(abi.encode(nonceDs, nonceEs)));

        // Compute rhos
        uint[] memory rhos = new uint[](threshold);
        for (uint i; i < threshold; i++) {
            rhos[i] = uint(keccak256(abi.encode(i, message, B)));
        }

        // Compute R
        Point memory G = LibSecp256k1.G().intoPoint();
        ProjectivePoint memory rProj = PointsLib.ProjectiveIdentity();
        for (uint i; i < threshold; i++) {
            ProjectivePoint memory D = G.toProjectivePoint().mul(nonceDs[i]);
            ProjectivePoint memory E = G.toProjectivePoint().mul(nonceEs[i]);
            rProj = rProj.add(D).add(E.mul(rhos[i]));
        }

        uint challenge =
            uint(keccak256(abi.encode(rProj.toPoint(), message))) % Q;

        // Compute s_i
        uint[] memory s = new uint[](threshold);
        for (uint i; i < threshold; i++) {
            uint index = indices[i];
            IIgloo.FunctionOutput[] memory encryptedFunctionOutputs =
                igloo.functionOutputs(index);
            uint a = uint(keccak256(abi.encodePacked("a", participants[i])));
            s[i] = _computeS(a, encryptedFunctionOutputs);
        }

        // Compute z_i
        uint[] memory zs = new uint[](threshold);
        for (uint i; i < threshold; i++) {
            uint lambda = _lagrangeCoefficients(indices[i], indices);
            zs[i] = addmod(nonceDs[i], mulmod(nonceEs[i], rhos[i], Q), Q);
            zs[i] =
                addmod(zs[i], mulmod(challenge, mulmod(lambda, s[i], Q), Q), Q);
        }
        uint z;
        for (uint i; i < threshold; i++) {
            z = addmod(z, zs[i], Q);
        }

        // Check the signature is valid
        // zG = R + cY
        ProjectivePoint memory Y =
            igloo.publicKey().intoPoint().toProjectivePoint();

        ProjectivePoint memory zG = G.toProjectivePoint().mul(z);
        ProjectivePoint memory cY = Y.mul(challenge);
        ProjectivePoint memory RcY = rProj.add(cY);
        assertEq(zG.toPoint().x.asUint(), RcY.toPoint().x.asUint());
    }

    // -- State Change Tests

    // TODO

    // -- Helper functions --

    function _performRound1(
        address[] memory participants,
        IIgloo igloo,
        uint threshold,
        bytes32 seed
    ) internal {
        // Iterate through every participant
        for (uint i; i < participants.length; i++) {
            uint participantIndex = igloo.index(participants[i]);
            // Ensure the participant state is correct
            _assertParticipantState(
                IIgloo.ParticipantState.ROUND_1,
                participantIndex,
                igloo
            );

            // Create coefficients
            uint[] memory coefficients =
                _randCoefficients(participants[i], threshold, seed);

            // Create the commitments
            Point[] memory commitments = _commitments(coefficients);

            // Create sigma proof
            uint k = uint(keccak256(abi.encodePacked("k", participants[i])));
            Point memory r = _mapToCurve(k);
            uint challenge = igloo.participantChallenge(
                participants[i], commitments[0], r
            );
            // mu = k + a_0 * c
            uint mu = (addmod(k, mulmod(challenge, coefficients[0], Q), Q));

            // Create channel
            uint a = uint(keccak256(abi.encodePacked("a", participants[i])));
            Point memory channelKey = _mapToCurve(a);

            // Share the commitments
            vm.prank(participants[i]);
            igloo.shareCommitments(
                i, commitments, IIgloo.Sigma(r, mu), channelKey
            );

            // Test submitting again fails

            // Ensure the participant state is correct
            if (i == participants.length - 1) {
                _assertGlobalState(
                    IIgloo.SessionState.ROUND_2, igloo
                );
                _assertParticipantState(
                    IIgloo.ParticipantState.ROUND_2,
                    participantIndex,
                    igloo
                );
            } else {
                _assertGlobalState(
                    IIgloo.SessionState.ROUND_1, igloo
                );
                _assertParticipantState(
                    IIgloo.ParticipantState.PENDING_ROUND_2,
                    participantIndex,
                    igloo
                );
            }
        }
    }

    function _performRound2(
        address[] memory participants,
        IIgloo igloo,
        uint threshold,
        bytes32 seed,
        uint[][] memory functionOutputs
    ) internal {
        Point[] memory channelKeys = igloo.channelKeys();
        uint[] memory indexes = new uint[](participants.length);

        // Iterate through every participant to find the index of each.
        for (uint i; i < participants.length; i++) {
            uint participantIndex = igloo.index(participants[i]);
            indexes[i] = participantIndex;
        }

        // Iterate through every participant and compute function outputs.
        for (uint i; i < participants.length; i++) {
            assertEq(
                uint(igloo.state(indexes[i])),
                uint(IIgloo.ParticipantState.ROUND_2),
                "Participant state is not ROUND_2"
            );

            // Participant needs to encrypt the function outputs and share them
            // with the other participants.
            IIgloo.FunctionOutput[] memory eFunctionOutputs =
                new IIgloo.FunctionOutput[](participants.length);
            for (uint j; j < participants.length; j++) {
                uint functionOutput = functionOutputs[i][j];

                eFunctionOutputs[j] = _encryptFunctionOutput(
                    functionOutput,
                    channelKeys[j],
                    keccak256(
                        abi.encodePacked(
                            "seed", participants[j], participants[i]
                        )
                    )
                );
            }

            // Share the function outputs.
            vm.prank(participants[i]);
            vm.expectEmit();
            address participant = participants[i];
            emit SharedFunctionOutputs(participant, eFunctionOutputs);
            if (i == participants.length - 1) {
                emit FunctionOutputsShared();
            }
            igloo.shareFunctionOutputs(i, eFunctionOutputs);

            // Check the attempting to submit outputs again fails.
            vm.prank(participants[i]);
            if (i == participants.length - 1) {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIgloo.InvalidParticipantState.selector,
                        participants[i],
                        IIgloo.ParticipantState.ROUND_2,
                        IIgloo.ParticipantState.ROUND_3
                    )
                );
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIgloo.InvalidParticipantState.selector,
                        participants[i],
                        IIgloo.ParticipantState.ROUND_2,
                        IIgloo.ParticipantState.PENDING_ROUND_3
                    )
                );
            }
            igloo.shareFunctionOutputs(i, eFunctionOutputs);

            if (i == participants.length - 1) {
                // Check the global state is correct
                assertEq(
                    uint(igloo.state()),
                    uint(IIgloo.SessionState.ROUND_3),
                    "Global state is not ROUND_3"
                );
                assertEq(
                    uint(igloo.state(i)),
                    uint(IIgloo.ParticipantState.ROUND_3),
                    "Participant state is not ROUND_3"
                );
            } else {
                // Check the global state is correct
                assertEq(
                    uint(igloo.state()),
                    uint(IIgloo.SessionState.ROUND_2),
                    "Global state is not ROUND_2"
                );
                // Check the participant state is correct
                assertEq(
                    uint(igloo.state(indexes[i])),
                    uint(IIgloo.ParticipantState.PENDING_ROUND_3),
                    "Participant state is not PENDING_ROUND_3"
                );
            }
        }
    }

    function _performRound3(
        address[] memory participants,
        IIgloo igloo,
        uint threshold,
        bytes32 seed,
        uint[][] memory functionOutputs
    ) internal {
        // We need to first validate all the function outputs are correct.
        _validateFunctionOutputs(
            participants, igloo, threshold, seed, functionOutputs
        );

        uint[] memory indexes = new uint[](participants.length);

        // Iterate through every participant to find the index of each.
        for (uint i; i < participants.length; i++) {
            uint participantIndex = igloo.index(participants[i]);
            indexes[i] = participantIndex;
        }

        // Iterate through every participant.
        for (uint i; i < participants.length; i++) {
            uint participantIndex = igloo.index(participants[i]);
            // Ensure the participant state is correct
            _assertParticipantState(
                IIgloo.ParticipantState.ROUND_3,
                participantIndex,
                igloo
            );

            // Check the global state is correct
            assertEq(
                uint(igloo.state()),
                uint(IIgloo.SessionState.ROUND_3),
                "Global state is not ROUND_3"
            );

            vm.prank(participants[i]);
            vm.expectEmit();
            if (i == participants.length - 1) {
                emit FunctionOutputsValidated();
            }
            emit ValidatedFunctionOutputs(participants[i]);
            igloo.validateFunctionOutputs(indexes[i]);

            // Check the state reverts if we try to validate again.
            vm.prank(participants[i]);
            if (i == participants.length - 1) {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIgloo.InvalidParticipantState.selector,
                        participants[i],
                        IIgloo.ParticipantState.ROUND_3,
                        IIgloo.ParticipantState.ACTIVE
                    )
                );
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIgloo.InvalidParticipantState.selector,
                        participants[i],
                        IIgloo.ParticipantState.ROUND_3,
                        IIgloo.ParticipantState.PENDING_ACTIVE
                    )
                );
            }
            igloo.validateFunctionOutputs(indexes[i]);

            // Check the global and participant state is correct.
            if (i == participants.length - 1) {
                assertEq(
                    uint(igloo.state()),
                    uint(IIgloo.SessionState.ACTIVE),
                    "Global state is not ACTIVE"
                );
                assertEq(
                    uint(igloo.state(i)),
                    uint(IIgloo.ParticipantState.ACTIVE),
                    "Participant state is not ACTIVE"
                );
            } else {
                // Check the global state is correct
                assertEq(
                    uint(igloo.state()),
                    uint(IIgloo.SessionState.ROUND_3),
                    "Global state is not ROUND_3"
                );
                // Check the participant state is correct
                assertEq(
                    uint(igloo.state(indexes[i])),
                    uint(IIgloo.ParticipantState.PENDING_ACTIVE),
                    "Participant state is not PENDING_ACTIVE"
                );
            }
        }
        ProjectivePoint memory Y =
            igloo.publicKey().intoPoint().toProjectivePoint();
    }

    function _validateFunctionOutputs(
        address[] memory participants,
        IIgloo igloo,
        uint threshold,
        bytes32 seed,
        uint[][] memory actualFunctionOutputs
    ) internal {
        vm.pauseGasMetering();
        Point memory G = LibSecp256k1.G().intoPoint();
        uint[] memory indexes = new uint[](participants.length);
        // Iterate through every participant.
        for (uint i; i < participants.length; i++) {
            uint participantIndex = igloo.index(participants[i]);
            indexes[i] = participantIndex;
        }
        for (uint i; i < participants.length; i++) {
            assertEq(
                uint(igloo.state(indexes[i])),
                uint(IIgloo.ParticipantState.ROUND_3),
                "Participant state is not ROUND_3"
            );

            // Check the the function outputs for this participant are correct
            IIgloo.FunctionOutput[] memory encryptedFunctionOutputs =
                igloo.functionOutputs(indexes[i]);
            uint a = uint(keccak256(abi.encodePacked("a", participants[i])));
            uint[] memory functionOutputs = new uint[](participants.length);
            for (uint j; j < participants.length; j++) {
                Point memory C1 = encryptedFunctionOutputs[j].C1;
                Point memory C2 = encryptedFunctionOutputs[j].C2;
                Point memory M = C2.toProjectivePoint().add(
                    C1.toProjectivePoint().mul(Q - a)
                ).toPoint();

                uint encryptedOutput = encryptedFunctionOutputs[j].eOutput;
                uint functionOuptut = addmod(
                    uint(encryptedOutput),
                    uint(Q - addmod(M.x.asUint(), Q, Q)),
                    Q
                );

                functionOutputs[j] = functionOuptut;
                assertEq(actualFunctionOutputs[j][i], functionOuptut);
            }

            uint s;
            for (uint j; j < functionOutputs.length; j++) {
                s = addmod(s, functionOutputs[j], Q);
            }
            Point memory Y = G.toProjectivePoint().mul(s).toPoint();
            Point[][] memory commitments = igloo.commitments();
            ProjectivePoint memory expectedYi = PointsLib.ProjectiveIdentity();
            for (uint j; j < participants.length; j++) {
                for (uint k; k < threshold; k++) {
                    uint x = i + 1;
                    x = _modExp(x, k, Q);
                    expectedYi = expectedYi.add(
                        commitments[j][k].toProjectivePoint().mul(x)
                    );
                }
            }
            assertEq(
                Y.x.asUint(),
                expectedYi.toPoint().x.asUint(),
                "Yi does not match expected Yi"
            );
        }
    }

    function _computeFunctionOutput(
        address[] memory participants,
        uint threshold,
        bytes32 seed
    ) internal view returns (uint[][] memory) {
        uint[][] memory functionOutputs = new uint[][](participants.length);
        for (uint i; i < participants.length; i++) {
            functionOutputs[i] = new uint[](participants.length);
            uint[] memory coefficients =
                _randCoefficients(participants[i], threshold, seed);
            for (uint j; j < participants.length; j++) {
                functionOutputs[i][j] = _evaluatePolynomial(coefficients, j + 1);
            }
        }
        return functionOutputs;
    }

    function _encryptFunctionOutput(
        uint functionOutput,
        Point memory channelKey,
        bytes32 seed
    ) internal view returns (IIgloo.FunctionOutput memory) {
        Point memory G = LibSecp256k1.G().intoPoint();
        uint m = uint(keccak256(abi.encodePacked("m", functionOutput, seed)));
        Point memory M = G.toProjectivePoint().mul(m).toPoint();
        uint k = uint(keccak256(abi.encodePacked("k", functionOutput, seed)));
        Point memory C1 = G.toProjectivePoint().mul(k).toPoint();
        Point memory C2 = M.toProjectivePoint().add(
            channelKey.toProjectivePoint().mul(k)
        ).toPoint();

        return IIgloo.FunctionOutput(
            addmod(uint(M.x.asUint()), uint(functionOutput), Q), C1, C2
        );
    }

    function _computeS(
        uint a,
        IIgloo.FunctionOutput[] memory encryptedFunctionOutputs
    ) internal returns (uint) {
        uint[] memory functionOutputs =
            new uint[](encryptedFunctionOutputs.length);
        for (uint j; j < encryptedFunctionOutputs.length; j++) {
            Point memory C1 = encryptedFunctionOutputs[j].C1;
            Point memory C2 = encryptedFunctionOutputs[j].C2;
            Point memory M = C2.toProjectivePoint().add(
                C1.toProjectivePoint().mul(Q - a)
            ).toPoint();

            uint encryptedOutput = encryptedFunctionOutputs[j].eOutput;
            uint functionOuptut = addmod(
                uint(encryptedOutput), uint(Q - addmod(M.x.asUint(), Q, Q)), Q
            );

            functionOutputs[j] = functionOuptut;
        }
        uint s;
        for (uint j; j < functionOutputs.length; j++) {
            s = addmod(s, functionOutputs[j], Q);
        }
        return s;
    }

    function _evaluatePolynomial(uint[] memory coefficients, uint x)
        internal
        view
        returns (uint)
    {
        uint result = 0;
        for (uint i; i < coefficients.length; i++) {
            uint x_ = _modExp(x, i, Q);
            result = addmod(result, mulmod(coefficients[i], x_, Q), Q);
        }
        return result;
    }

    function _assertGlobalState(
        IIgloo.SessionState expectedState,
        IIgloo igloo
    ) internal view {
        assertEq(
            uint(igloo.state()),
            uint(expectedState),
            "Global state is not expected"
        );
    }

    function _assertParticipantState(
        IIgloo.ParticipantState expectedState,
        uint participantIndex,
        IIgloo igloo
    ) internal view {
        assertEq(
            uint(igloo.state(participantIndex)),
            uint(expectedState),
            "Participant state is not expected"
        );
    }

    function _modExp(uint base, uint exponent, uint modulus)
        internal
        view
        returns (uint result)
    {
        assembly ("memory-safe") {
            // Free memory pointer
            let memPtr := mload(0x40)

            // Length of base, exponent, modulus
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)

            // Store base, exponent, and modulus
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), exponent)
            mstore(add(memPtr, 0xA0), modulus)

            // Call the precompiled contract
            let success := staticcall(gas(), 0x05, memPtr, 0xC0, memPtr, 0x20)

            // Return the result
            result := mload(memPtr)
        }
    }

    function _randParticipants(uint numParticipants, bytes32 seed)
        internal
        pure
        returns (address[] memory)
    {
        address[] memory participants = new address[](numParticipants);
        for (uint i; i < participants.length; i++) {
            seed = keccak256(abi.encodePacked("_randParticipants", seed, i));
            participants[i] = address(uint160(uint(seed)));
        }
        return participants;
    }

    function _randCoefficients(
        address participant,
        uint threshold,
        bytes32 seed
    ) internal pure returns (uint[] memory) {
        uint[] memory coefficients = new uint[](threshold);
        for (uint i; i < coefficients.length; i++) {
            seed = keccak256(
                abi.encodePacked("_randCoefficients", seed, i, participant)
            );
            coefficients[i] = uint(seed) % Q;
        }
        return coefficients;
    }

    function _commitments(uint[] memory coefficients)
        internal
        view
        returns (Point[] memory)
    {
        Point[] memory commitments = new Point[](coefficients.length);

        for (uint i; i < coefficients.length; i++) {
            commitments[i] = _mapToCurve(coefficients[i]);
        }

        return commitments;
    }

    function _mapToCurve(uint k) internal view returns (Point memory) {
        Point memory G = LibSecp256k1.G().intoPoint();
        return G.toProjectivePoint().mul(k).toPoint();
    }

    function _lagrangeCoefficients(uint i, uint[] memory indices)
        internal
        returns (uint)
    {
        uint numerator = 1;
        uint denominator = 1;
        i = i + 1;
        for (uint j; j < indices.length; j++) {
            if (indices[j] + 1 != i) {
                numerator = mulmod(numerator, indices[j] + 1, Q);
                denominator =
                    mulmod(denominator, addmod(indices[j] + 1, Q - i, Q), Q);
            }
        }

        // Calculate modular inverse of the denominator
        uint denominatorInv = _modExp(denominator, Q - 2, Q);
        // Final Lagrange coefficient
        return mulmod(numerator, denominatorInv, Q);
    }
}
