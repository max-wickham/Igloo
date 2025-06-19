// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Secp256k1 as LibSecp256k1, PublicKey} from "crysol/Secp256k1.sol";
import {
    Point,
    ProjectivePoint,
    Points as PointsLib
} from "crysol/arithmetic/Points.sol";
import {Felt, Fp} from "crysol/arithmetic/Fp.sol";

import {IIgloo} from "./IIgloo.sol";

/*
    This contract is used to perform the key generation ceremony for a frost key as described in 
    the 2020 paper "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" by 
    Chelsea Komlo and Ian Goldberg.  https://eprint.iacr.org/2020/852.

    Frost signatures allow the secret sharing among n participants a key that can be used to 
    create a valid schnorr signature using a threshold of t participants. Each participant's resultant 
    secret at the end of the ceremony is dependent on state generated during the ceremony. For this 
    reason when signing messages using Frost, participants must be aware of the state of the
    ceremony. By using a smart contract to perform the ceremony it is easy to ensure every participant
    can easily query the ceremony state without having to store the state on their locally.

    Each deployment of this contract (via proxy) supports a single key generation ceremony.
    The contract is initialized with the participants and threshold.

    The Key generation ceremony is performed in 3 rounds:

    (t) = threshold
    (n) = number of participants
    
    1. Commitment Sharing
        - Each participant shares a commitment to t polynomial coefficients.
        - Each participant provides proof of knowledge of the first coefficient.
            with a value sigma = (R, mu). This proof is confirmed by the contract.
        - Each participant provides a curve point A where a is such that A = aG is secretly known,
            this is used to encrypt messages sent to this participant.
        - After this stage each participant enters state "PENDING_ROUND_2" until every participant
            has completed this stage.
    2. Encrypted Function Output Sharing
        - Each participant evaluates their polynomial function (defined by the coefficients generated earlier)
            at each participants index and uses the corresponding participants 
            channel key A to encrypt the message.
        - Not the indexes provided by query the "index" function start at 0, however, when evaluating
            the polynomial at the participants index the start index is expected to be 1. For this reason
            1 must be added to the index before evaluating the polynomial.
        - After this stage each participant enters state "PENDING_ROUND_3" until every participant
            has completed this stage.
    3. Validation of function outputs
        - Each participant queries and decrypts the polynomial outputs evaluated at their index,
            each of these outputs is validated by using the prior commitments
        - After this stage each participant enters state "PENDING_ACTIVE" until every participant
            has completed this stage
        - Once this stage has been completed by all validators the key is ACTIVE and the validators can
            compute their partial keys by the sum of the polynomials evaluated at their index.

    At the end of the ceremony the Schnorr Public key can be queried from the contract.
    Participants should check that this contract before signing messages to check no other participant has deprecated the
    key.
*/

/**
 * @title Igloo
 * @custom:version 0.1.0
 *
 * @notice Coordinator for a Frost key generation ceremony.
 *
 */
contract Igloo is IIgloo {
    using LibSecp256k1 for PublicKey;
    using PointsLib for Point;
    using PointsLib for ProjectivePoint;
    using Fp for Felt;

    /// @notice Session stores the state of a key generation ceremony.
    struct Session {
        // -- Starting state --
        SessionState round;
        // -- Round 1 --
        Point[][] commitments; // (n x t) Commitments to polynomial coefficients.
        Sigma[] sigmas; // (n) Proof of knowledge of first coefficient.
        Point[] sessionChannelKeys; // (n) Public channel encryption keys `(A = aG)`, `a` is kept secret by participant.
        uint commitmentsCount; // Number of participants who have submitted commitments.
        bool[] commitmentsSubmitted; // (n) Marked true if a participant has completed this stage.
        // -- Round 2 --
        FunctionOutput[][] encryptedFunctionOutputs; // (n x n) Encrypted function outputs,
        // f_i(j) = decrypt(encryptedFunctionOutputs[i][j])
        uint functionOutputCount;
        bool[] functionOutputsSubmitted; // (n) Marked true if a participant has completed this stage.
        // -- Round 3 --
        uint validationCount;
        bool[] validatedFunctionOutputs; // (n) Marked true if a participant has validated the receiving function outputs
    }

    /// @dev The order of the secp256k1 curve.
    uint constant Q =
        115792089237316195423570985008687907852837564279074904382605163141518161494337;

    address[] internal _participants;
    uint public threshold;

    PublicKey private _publicKey;
    Session private _session;

    /// @dev The constructor is empty due to the use of a proxy pattern.
    constructor() {
        // Prevent initialization of the contract, (other than via proxy).
        threshold = 1;
    }

    function init(address[] memory participants_, uint threshold_) public {
        // Must not be previously initialized.
        require(threshold == 0, "Already initialized");
        // Must be at least threshold participants
        require(participants_.length >= threshold_, "Participants < threshold");
        // Threshold must be greater than 0.
        require(threshold_ > 0, "Threshold == 0");

        // Store key parameters.
        threshold = threshold_;
        _participants = participants_;

        // Initialize ceremony session state.
        Session memory session;
        uint numParticipants = participants_.length;
        session.commitments = new Point[][](numParticipants);
        session.sigmas = new Sigma[](numParticipants);
        session.commitmentsSubmitted = new bool[](numParticipants);
        session.sessionChannelKeys = new Point[](numParticipants);
        session.encryptedFunctionOutputs =
            new FunctionOutput[][](_participants.length);
        session.functionOutputsSubmitted = new bool[](numParticipants);
        session.validatedFunctionOutputs = new bool[](numParticipants);

        // Store the initialized session.
        _session = session;
    }

    // -- Modifiers --

    /// @dev Ensure participantIndex matches msg.sender.
    modifier checkParticipant(uint participantIndex) {
        if (_participants[participantIndex] != msg.sender) {
            revert InvalidParticipantIndex(
                participantIndex, _participants[participantIndex], msg.sender
            );
        }
        _;
    }

    /// @dev Ensure the participant index state is as expected.
    modifier checkState(uint participantIndex, ParticipantState round) {
        ParticipantState actualRound = state(participantIndex);
        if (actualRound != round) {
            revert InvalidParticipantState(msg.sender, round, actualRound);
        }
        _;
    }

    // -- General State --

    function participants() external view override returns (address[] memory) {
        return _participants;
    }

    // -- Session State --

    /// @inheritdoc IIgloo
    function publicKey() public view returns (PublicKey memory) {
        return _publicKey;
    }

    /// @inheritdoc IIgloo
    function state() public view returns (SessionState) {
        return _session.round;
    }

    /// @inheritdoc IIgloo
    function state(uint participantIndex)
        public
        view
        returns (ParticipantState)
    {
        SessionState round = _session.round;

        // If round one check if already submitted
        if (round == SessionState.ROUND_1) {
            if (_session.commitmentsSubmitted[participantIndex]) {
                return ParticipantState.PENDING_ROUND_2;
            }
            return ParticipantState.ROUND_1;
        }

        // If round 2 check if already submitted
        if (_session.round == SessionState.ROUND_2) {
            if (_session.functionOutputsSubmitted[participantIndex]) {
                return ParticipantState.PENDING_ROUND_3;
            }
            return ParticipantState.ROUND_2;
        }

        // If round 3 check if already submitted
        if (_session.round == SessionState.ROUND_3) {
            if (_session.validatedFunctionOutputs[participantIndex]) {
                return ParticipantState.PENDING_ACTIVE;
            }
            return ParticipantState.ROUND_3;
        }

        // Only other available option is ACTIVE.
        return ParticipantState.ACTIVE;
    }

    /// @inheritdoc IIgloo
    function channelKeys() public view returns (Point[] memory) {
        return _session.sessionChannelKeys;
    }

    /// @inheritdoc IIgloo
    function functionOutputs(uint participantIndex)
        public
        view
        returns (FunctionOutput[] memory)
    {
        uint numParticipants = _participants.length;

        // There should be one function evaluated on the participants index
        // for each participant.
        // This function is essentially taking a column of the encryptedFunctionOutputs matrix.
        FunctionOutput[] memory _functionOutputs =
            new FunctionOutput[](numParticipants);

        // Iterate through the submitted participant outputs
        // and select the index corresponding to the required
        // participant.
        for (uint i; i < numParticipants; i++) {
            _functionOutputs[i] =
                _session.encryptedFunctionOutputs[i][participantIndex];
        }
        return _functionOutputs;
    }

    /// @inheritdoc IIgloo
    function commitments() public view returns (Point[][] memory) {
        // Return all the commitments
        return _session.commitments;
    }

    /// @inheritdoc IIgloo
    function index(address participant) external view returns (uint) {
        for (uint i; i < _participants.length; i++) {
            if (_participants[i] == participant) {
                return i;
            }
        }
        return 0;
    }

    // -- Round 1 --

    /// @inheritdoc IIgloo
    function shareCommitments(
        uint participantIndex,
        Point[] calldata commitment,
        Sigma memory sigma,
        Point calldata channelKey
    )
        public
        checkParticipant(participantIndex)
        checkState(participantIndex, ParticipantState.ROUND_1)
    {
        // Number of commitments should equal threshold (t)
        require(commitment.length == threshold, "len(commitment) != threshold");

        // Store the commitment at the participant index.
        _session.commitments[participantIndex] = commitment;

        // Store the sigma value, used to prove knowledge of the scalar used
        // to generate commitment[0].
        _session.sigmas[participantIndex] = sigma;

        // Store the channel key used by other participants to encrypt their
        // functions computed on this participants index.
        _session.sessionChannelKeys[participantIndex] = channelKey;

        // Set commitments submitted to true, marking that this participant has completed
        // this step.
        _session.commitmentsSubmitted[participantIndex] = true;

        Point memory G = LibSecp256k1.G().intoPoint();

        // Verify the proof of knowledge of the first coefficient using sigma.
        // R + c_i * A_i_0 = mu * G

        // First find the challenge c_i
        uint challenge =
            participantChallenge(msg.sender, commitment[0], sigma.R);

        // Then require R + c_i * A_i_0 = mu * G
        require(
            sigma.R.toProjectivePoint().add(
                commitment[0].toProjectivePoint().mul(challenge)
            ).toPoint().eq(G.toProjectivePoint().mul(sigma.mu).toPoint()),
            "Sigma not verified"
        );

        emit SharedCommitment(msg.sender, commitment, sigma, channelKey);

        // Increase the commitment counter by 1 to keep track of how many
        // participants have completed this stage.
        _session.commitmentsCount += 1;

        // Check if this is the final participant to submit.
        if (_session.commitmentsCount == _participants.length) {
            // Set the session Round to ROUND_2.
            _session.round = SessionState.ROUND_2;

            // Compute the public key that will be the result of the ceremony.
            // Equal to the sum of all 0 index commitments.
            ProjectivePoint memory publicKeyProjectivePoint =
                PointsLib.ProjectiveIdentity();
            for (uint i; i < _participants.length; i++) {
                publicKeyProjectivePoint = publicKeyProjectivePoint.add(
                    _session.commitments[i][0].toProjectivePoint()
                );
            }

            Point memory publicKeyPoint = publicKeyProjectivePoint.toPoint();
            PublicKey memory key = LibSecp256k1.publicKeyFromFelts(
                publicKeyPoint.x, publicKeyPoint.y
            );
            _publicKey = key;

            emit CommitmentsShared(key);
        }
    }

    // -- Round 2 --

    /// @inheritdoc IIgloo
    function shareFunctionOutputs(
        uint participantIndex,
        FunctionOutput[] calldata encryptedFunctionOutputs
    )
        public
        checkParticipant(participantIndex)
        checkState(participantIndex, ParticipantState.ROUND_2)
    {
        // Ensure the number of function outputs is equal to the number of participants.
        require(
            encryptedFunctionOutputs.length == _participants.length,
            "len(outputs) != len(participants)"
        );

        // Mark that this participant has completed this stage.
        _session.functionOutputsSubmitted[participantIndex] = true;

        // Store the function outputs.
        _session.encryptedFunctionOutputs[participantIndex] =
            encryptedFunctionOutputs;

        // Increase the function output counter to keep track of how many participants have
        // completed this stage.
        _session.functionOutputCount += 1;

        emit SharedFunctionOutputs(msg.sender, encryptedFunctionOutputs);

        // If all participants have completed this stage increase the session state
        // to ROUND_3.
        if (_session.functionOutputCount == _participants.length) {
            _session.round = SessionState.ROUND_3;

            emit FunctionOutputsShared();
        }
    }

    // -- Round 3 --

    /// @inheritdoc IIgloo
    function validateFunctionOutputs(uint participantIndex)
        public
        checkParticipant(participantIndex)
        checkState(participantIndex, ParticipantState.ROUND_3)
    {
        // Mark that this participant has completed this stage.
        _session.validatedFunctionOutputs[participantIndex] = true;

        // Increase the validation count to keep track of how many participants
        // have completed this stage.
        _session.validationCount += 1;

        emit ValidatedFunctionOutputs(msg.sender);

        // If all participants have completed this stage then mark the final key as active.
        if (_session.validationCount == _participants.length) {
            _session.round = SessionState.ACTIVE;
            emit FunctionOutputsValidated();
        }
    }

    // -- Failure and Deprecation --

    /// @inheritdoc IIgloo
    function failKeyGeneration(uint participantIndex)
        public
        checkParticipant(participantIndex)
    {
        SessionState round = _session.round;

        // Check the the key is not ACTIVE, DEPRECATED or FAILED.
        require(round != SessionState.ACTIVE, "state == ACTIVE");
        require(round != SessionState.DEPRECATED, "state == DEPRECATED");
        require(round != SessionState.FAILED, "state == FAILED");

        // Mark the key as failed.
        _session.round = SessionState.FAILED;

        // Emit to indicate ceremony has failed.
        emit FailedKeyGeneration(msg.sender);
    }

    /// @inheritdoc IIgloo
    function deprecateKey(uint participantIndex)
        public
        checkParticipant(participantIndex)
    {
        SessionState round = _session.round;

        // Ensure the key is currently active.
        require(round == SessionState.ACTIVE, "state != ACTIVE");

        // Mark the key as DEPRECATED.
        _session.round = SessionState.DEPRECATED;

        // Emit to indicate key is active.
        emit DeprecatedKey(msg.sender);
    }

    // -- Helper Functions --

    /// @inheritdoc IIgloo
    function participantChallenge(
        address participant,
        Point memory phi,
        Point memory r
    ) public view returns (uint) {
        return uint(
            keccak256(
                abi.encodePacked(
                    "Commitment Hash", address(this), participant, phi.x, r.x
                )
            )
        ) % Q;
    }
}
