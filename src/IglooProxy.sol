// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";

/**
 * @title IglooProxy
 *
 * @notice Proxy contract for the Igloo contract.
 */
contract IglooProxy is Proxy {
    address public immutable igloo;

    constructor(address _igloo) {
        igloo = _igloo;
    }

    function _implementation() internal view override returns (address) {
        return igloo;
    }
}
