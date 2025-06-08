// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {IglooProxyFactory} from "../src/IglooProxyFactory.sol";

contract ProxyScript is Script { 


    function deploy(address singleton, address factory, string memory salt, address[] memory participants, uint threshold) public virtual {
        bytes32 saltHash = keccak256(abi.encodePacked(salt));

        IglooProxyFactory factory = IglooProxyFactory(factory);

        vm.startBroadcast();
        address deployed = factory.createProxy(
            singleton,
            participants,
            threshold,
            saltHash
        );

        vm.stopBroadcast();

        console.log("Deployed at", deployed);
    }

    function run() public {
        bytes memory bytecode = type(IglooProxyFactory).creationCode;
        console.logBytes(bytecode);
    }

}


