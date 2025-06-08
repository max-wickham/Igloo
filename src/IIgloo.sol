// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PublicKey} from "crysol/Secp256k1.sol";
import {Point} from "crysol/arithmetic/Points.sol";

interface IIgloo {
    /// @notice Function output stores the output of participant i's polynomial
    ///         evaluated at participant j's index.
    ///
    /// @dev To Encrypt:
    ///        1. Generate random curve point M
    ///        2. Generate k such that 1 < k < q
    ///        3. C1 = k * G
    ///        4. C2 = M + k * A_j (A_j is the receivers channel key)
    ///        4. encryptedOutput = (M.x + output) % q
    ///
    /// @dev To Decrypt:
    ///        1. M = C2 - a_jC1 (a_j is the receivers secret key such that A = aG)
    ///        2. output = (encryptedOutput - M.x)  % q (output should be the senders polynomial
    ///           evaluated on the receivers index (j))
    struct FunctionOutput {
        uint eOutput;
        Point C1;
        Point C2;
    }

    /// @notice SessionState is used to track the round of the key generation ceremony.
    enum SessionState {
        ROUND_1,
        ROUND_2,
        ROUND_3,
        ACTIVE,
        DEPRECATED,
        FAILED
    }

    /// @notice ParticipantState is used to track the round state of a
    ///         participant in the key generation ceremony.
    enum ParticipantState {
        ROUND_1,
        PENDING_ROUND_2,
        ROUND_2,
        PENDING_ROUND_3,
        ROUND_3,
        PENDING_ACTIVE,
        ACTIVE
    }

    /// @notice Sigma is used to prove knowledge of the
    ///         first coefficient of the participants polynomial
    /// @dev    R = k * G where k is a random scalar
    ///         and mu = k + a_0 _ + c where a_0 is the first coefficient
    ///         and c is the challenge computed using `participantChallenge`.
    struct Sigma {
        Point R;
        uint mu;
    }

    /// @notice Raised if the participant index does not match the msg.sender.
    error InvalidParticipantIndex(uint index, address participant, address sender );

    /// @notice Raised if a participant calls a function whilst not in the correct session state.
    error InvalidParticipantState(
        address sender,
        ParticipantState expectedRound,
        ParticipantState actualRound
    );

    /// @notice Emitted when a participant shares their commitments.
    ///
    /// @param sender The participant the shared the commitments.
    /// @param commitment The list of commitments of length threshold (t).
    /// @param sigma Used to prove knowledge of the first coefficient corresponding
    ///              to the first coefficient.
    /// @param channelKey A key that can be used to send asymmetrically encrypted data
    ///                   to this participant.
    event SharedCommitment(
        address indexed sender,
        Point[] commitment,
        Sigma sigma,
        Point channelKey
    );

    /// @notice Emitted when all commitments shared.
    ///
    /// @param publicKey The public key calculated from the commitments.
    event CommitmentsShared(PublicKey publicKey);

    /// @notice Emitted when a participant submits their outputs.
    event SharedFunctionOutputs(
        address indexed participant, FunctionOutput[] encryptedFunctionOutputs
    );

    /// @notice Emitted when all function outputs have been shared.
    event FunctionOutputsShared();

    /// @notice Emitted when a participant validates the function outputs evaluated on
    ///         their index.
    event ValidatedFunctionOutputs(address indexed participant);

    /// @notice Emitted when all function outputs have been validated, activating the key.
    event FunctionOutputsValidated();

    /// @notice Emitted if a participant marks the key generation ceremony as failed.
    event FailedKeyGeneration(address sender);

    /// @notice Emitted when the key has been deprecated by one of the participants.
    event DeprecatedKey(address sender);

    /// @notice Used to initialize the key generation ceremony
    ///         as part of the proxy pattern.
    function init(address[] memory participants, uint threshold) external;

    /// @notice Returns the Public Key created after
    ///         completion of the key generation ceremony.
    function publicKey() external view returns (PublicKey memory);

    /// @notice Returns the list of participants involved in the ceremony.
    function participants() external view returns (address[] memory);

    /// @notice Returns the threshold defined for this ceremony,
    ///         defines the number of participants required to create
    ///         a valid signature.
    function threshold() external view returns (uint);

    /// @notice Returns the index of a specific participant.
    function index(address participant) external view returns (uint);

    /// @notice Returns the current state of the key generation ceremony.
    /// @notice The key should not be used before the state is set to active.
    /// @notice Any participant can "deprecate" the key at any time as a warning
    ///         to other participants that the key should not be used.
    function state() external view returns (SessionState);

    /// @notice Returns the participant level state in the key generation ceremony.
    function state(uint participantIndex)
        external
        view
        returns (ParticipantState);

    /// @notice Returns the list of participant channel keys,
    ///         used to send encrypted function outputs between participants.
    function channelKeys() external view returns (Point[] memory);

    /// @notice List of encrypted function outputs evaluated on the current participant index.
    ///         [encrypted(f_0(participantIndex)), encrypted(f_1(participantIndex))....]
    function functionOutputs(uint participantIndex)
        external
        view
        returns (FunctionOutput[] memory);

    /// @notice Returns an `(n x t)` array of submitted polynomial coefficient commitments.
    ///         where `t` is the threshold and `n` the number of participants.
    function commitments() external view returns (Point[][] memory);

    // -- Round 1 --

    /// @notice Used to submit commitments, sigma and channelKey.
    ///
    /// @param participantIndex The index of the participant submitting data, (found using index(address)).
    /// @param commitment A list of threshold points committing to each of the participants
    ///                   function coefficients, (commitment[i] == coefficient[i] * G).
    /// @param sigma Proof of knowledge of the first coefficient given the commitment.
    /// @param channelKey Public Key used to encrypt data to send to this participant.
    function shareCommitments(
        uint participantIndex,
        Point[] calldata commitment,
        Sigma memory sigma,
        Point calldata channelKey
    ) external;

    // -- Round 2 --

    /// @notice Used to the output of this participants function evaluated on each participants index.
    ///
    /// @param participantIndex The index of the participant submitting data, (found using index(address)).
    /// @param encryptedFunctionOutputs The participants polynomial function run on each participants index,
    ///                                 (counting from 1). Each function output is encrypted using the
    ///                                 the corresponding participants encryption key.
    function shareFunctionOutputs(
        uint participantIndex,
        FunctionOutput[] calldata encryptedFunctionOutputs
    ) external;

    // -- Round 3 --

    /// @notice Used to validate that all the function outputs operated on this participants index are
    ///         as expected.
    ///
    /// @param participantIndex The index of the participant submitting data, (found using index(address)).
    function validateFunctionOutputs(uint participantIndex) external;

    // -- Failure and Deprecation

    /// @notice Called by a participant if they need to fail the ceremony due to failure of a stage.
    ///
    /// @param participantIndex The index of the participant submitting data, (found using index(address)).
    function failKeyGeneration(uint participantIndex) external;

    /// @notice Called by a participant to mark the key as deprecated, should be used if the
    ///         participants secret key has been leaked.
    ///
    /// @param participantIndex The index of the participant submitting data, (found using index(address)).
    function deprecateKey(uint participantIndex) external;

    // -- Helper Functions --

    /// @notice Used by a participant to construct the proof of knowledge of its first coefficient.
    ///
    /// @param participant Address of the participant to compute the challenge
    /// @param phi Coefficient zero of the participant.
    /// @param r The value R - k * G, used in sigma as part of the participants proof of knowledge.
    function participantChallenge(
        address participant,
        Point memory phi,
        Point memory r
    ) external view returns (uint);
}
