// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IglooProxy} from "./IglooProxy.sol";

/**
 * @title IglooProxyFactory
 *
 * @notice Factory contract for creating IglooProxy instances.
 *
 */
contract IglooProxyFactory {
    event ProxyCreated(address indexed proxy, address singleton);

    function createProxy(
        address _singleton,
        address[] memory participants,
        uint threshold,
        bytes32 salt
    ) external returns (address) {
        salt =
            keccak256(abi.encodePacked(keccak256(abi.encode(_singleton)), salt));

        require(exists(_singleton), "Singleton contract not deployed");

        bytes memory deploymentData = abi.encodePacked(
            type(IglooProxy).creationCode, uint(uint160(_singleton))
        );

        address proxy;
        assembly {
            proxy :=
                create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }

        require(proxy != address(0), "Proxy creation failed");

        // Initialize the proxy with the singleton contract
        bytes memory initializer = abi.encodeWithSignature(
            "init(address[],uint256)", participants, threshold
        );
        assembly {
            if eq(
                call(
                    gas(),
                    proxy,
                    0,
                    add(initializer, 0x20),
                    mload(initializer),
                    0,
                    0
                ),
                0
            ) { revert(0, 0) }
        }

        emit ProxyCreated(proxy, _singleton);

        return proxy;
    }

    function exists(address account) internal view returns (bool) {
        uint size;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
