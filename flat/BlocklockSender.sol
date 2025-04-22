// SPDX-License-Identifier: MIT
pragma solidity ^0.8 ^0.8.20 ^0.8.22 ^0.8.4;

// lib/openzeppelin-contracts/contracts/access/IAccessControl.sol

// OpenZeppelin Contracts (last updated v5.1.0) (access/IAccessControl.sol)

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// lib/openzeppelin-contracts/contracts/interfaces/IERC1967.sol

// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC1967.sol)

/**
 * @dev ERC-1967: Proxy Storage Slots. This interface contains the events defined in the ERC.
 */
interface IERC1967 {
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);
}

// lib/openzeppelin-contracts/contracts/interfaces/draft-IERC1822.sol

// OpenZeppelin Contracts (last updated v5.1.0) (interfaces/draft-IERC1822.sol)

/**
 * @dev ERC-1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}

// lib/openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/beacon/IBeacon.sol)

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {UpgradeableBeacon} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

// lib/openzeppelin-contracts/contracts/utils/Errors.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/Errors.sol)

/**
 * @dev Collection of common custom errors used in multiple contracts
 *
 * IMPORTANT: Backwards compatibility is not guaranteed in future versions of the library.
 * It is recommended to avoid relying on the error API for critical functionality.
 *
 * _Available since v5.1._
 */
library Errors {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error InsufficientBalance(uint256 balance, uint256 needed);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedCall();

    /**
     * @dev The deployment failed.
     */
    error FailedDeployment();

    /**
     * @dev A necessary precompile is missing.
     */
    error MissingPrecompile(address);
}

// lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}

// lib/openzeppelin-contracts/contracts/utils/StorageSlot.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC-1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     // Define the slot. Alternatively, use the SlotDerivation library to derive the slot.
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * TIP: Consider using this library along with {SlotDerivation}.
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct Int256Slot {
        int256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Int256Slot` with member `value` located at `slot`.
     */
    function getInt256Slot(bytes32 slot) internal pure returns (Int256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns a `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }
}

// lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/introspection/IERC165.sol)

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/structs/EnumerableSet.sol)
// This file was procedurally generated from scripts/generate/templates/EnumerableSet.js.

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)
 * and `uint256` (`UintSet`) are supported.
 *
 * [WARNING]
 * ====
 * Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * unusable.
 * See https://github.com/ethereum/solidity/pull/11843[ethereum/solidity#11843] for more info.
 *
 * In order to clean an EnumerableSet, you can either remove all elements one by one or create a fresh instance using an
 * array of EnumerableSet.
 * ====
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(bytes32 value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                bytes32 lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set) private view returns (bytes32[] memory) {
        return set._values;
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set) internal view returns (bytes32[] memory) {
        bytes32[] memory store = _values(set._inner);
        bytes32[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(UintSet storage set) internal view returns (uint256[] memory) {
        bytes32[] memory store = _values(set._inner);
        uint256[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }
}

// lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/Initializable.sol)

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}

// src/interfaces/IBlocklockReceiver.sol

/// @title IBlocklockReceiver interface
/// @author Randamu
/// @notice Interface for user contracts receiving decryption keys via callbacks.
interface IBlocklockReceiver {
    /// @notice Receives a blocklock decryption key associated with a specific request.
    /// @dev This function is called to provide the blocklock decryption generated for a
    /// given request ID.
    /// It is intended to be called by a trusted source that provides the decryption key.
    /// @param requestID The unique identifier of the blocklock request.
    /// @param decryptionKey The generated random value, provided as a `bytes` type.
    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external;
}

// src/interfaces/ISubscription.sol

/// @notice ISubscription interface
/// @notice interface for contracts supporting user subscription for an onchain service.
/// @notice Inspired by Chainlink's IVRFSubscriptionV2Plus. Source code at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/vrf/dev/interfaces/IVRFSubscriptionV2Plus.sol
/// @notice License: MIT
interface ISubscription {
    /// @notice Add a consumer to a subscription.
    /// @param subId - ID of the subscription
    /// @param consumer - New consumer which can use the subscription
    function addConsumer(uint256 subId, address consumer) external;

    /// @notice Remove a consumer from a subscription.
    /// @param subId - ID of the subscription
    /// @param consumer - Consumer to remove from the subscription
    function removeConsumer(uint256 subId, address consumer) external;

    /// @notice Cancel a subscription
    /// @param subId - ID of the subscription
    /// @param to - Where to send the remaining subscription balance to
    function cancelSubscription(uint256 subId, address to) external;

    /// @notice Accept subscription owner transfer.
    /// @param subId - ID of the subscription
    /// @dev will revert if original owner of subId has
    /// not requested that msg.sender become the new owner.
    function acceptSubscriptionOwnerTransfer(uint256 subId) external;

    /// @notice Request subscription owner transfer.
    /// @param subId - ID of the subscription
    /// @param newOwner - proposed new owner of the subscription
    function requestSubscriptionOwnerTransfer(uint256 subId, address newOwner) external;

    /// @notice Create a subscription.
    /// @return subId - A unique subscription id.
    /// @dev You can manage the consumer set dynamically with addConsumer/removeConsumer.
    /// @dev Note to fund the subscription with Native, use fundSubscriptionWithNative. Be sure
    /// @dev  to send Native with the call, for example:
    /// @dev COORDINATOR.fundSubscriptionWithNative{value: amount}(subId);
    function createSubscription() external returns (uint256 subId);

    /// @notice Get a subscription.
    /// @param subId - ID of the subscription
    /// @return nativeBalance - native balance of the subscription in wei.
    /// @return reqCount - Requests count of subscription.
    /// @return owner - owner of the subscription.
    /// @return consumers - list of consumer address which are able to use this subscription.
    function getSubscription(uint256 subId)
        external
        view
        returns (uint96 nativeBalance, uint64 reqCount, address owner, address[] memory consumers);

    /// @notice Check to see if there exists a request commitment consumers
    /// for all consumers and keyhashes for a given sub.
    /// @param subId - ID of the subscription
    /// @return true if there exists at least one unfulfilled request for the subscription, false
    /// otherwise.
    function pendingRequestExists(uint256 subId) external view returns (bool);

    /// @notice Paginate through all active subscriptions.
    /// @param startIndex index of the subscription to start from
    /// @param maxCount maximum number of subscriptions to return, 0 to return all
    /// @dev the order of IDs in the list is///*not guaranteed**, therefore, if making successive calls, one
    /// @dev should consider keeping the blockheight constant to ensure a holistic picture of the contract state
    function getActiveSubscriptionIds(uint256 startIndex, uint256 maxCount) external view returns (uint256[] memory);

    /// @notice Fund a subscription with native.
    /// @param subId - ID of the subscription
    /// @notice This method expects msg.value to be greater than or equal to 0.
    function fundSubscriptionWithNative(uint256 subId) external payable;
}

// src/libraries/BytesLib.sol

/// @title BytesLib library
/// @author Randamu
/// @notice Utility library for bytes-related operations
library BytesLib {
    /// @dev Checks if a bytes array is empty.
    /// @param data The bytes array to check.
    /// @return bool Returns true if the bytes array is empty, false otherwise.
    function isEmpty(bytes memory data) internal pure returns (bool) {
        return data.length == 0;
    }

    /// @dev Checks if all bytes in a bytes array are zero.
    /// @param data The bytes array to check.
    /// @return bool Returns true if all bytes are zero, false if at least one byte is non-zero.
    function isAllZero(bytes memory data) internal pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0x00) {
                return false; // Found a non-zero byte
            }
        }
        return true; // All bytes are zero
    }

    /// @dev Checks if the length of a bytes array is within the given bounds.
    /// @param data The bytes array to check.
    /// @param minLength The minimum length that the bytes array must be.
    /// @param maxLength The maximum length that the bytes array must be.
    /// @return bool Returns true if the length of the bytes array is within [minLength, maxLength], false otherwise.
    /// @notice Reverts if minLength is greater than maxLength.
    function isLengthWithinBounds(bytes memory data, uint256 minLength, uint256 maxLength)
        internal
        pure
        returns (bool)
    {
        require(minLength <= maxLength, "Invalid bounds: minLength cannot be greater than maxLength");
        uint256 dataLength = data.length;
        return dataLength >= minLength && dataLength <= maxLength;
    }

    /// @dev Decodes a bytes array back to a uint256.
    /// @param data The bytes array to decode.
    /// @return uint256 The decoded uint256 value.
    /// @notice Reverts if the length of the bytes array is less than 32 bytes.
    function decodeBytesToUint(bytes memory data) internal pure returns (uint256) {
        require(data.length >= 32, "Data must be at least 32 bytes long");
        return abi.decode(data, (uint256)); // Decode bytes back to uint
    }

    /// @dev Converts bytes32 to 0x-prefixed hex string.
    /// @param data The bytes32 data to convert.
    function toHexString(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(2 + 64); // "0x" + 64 hex chars
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = hexChars[uint8(data[i] >> 4)];
            str[2 + i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}

// src/libraries/ModExp.sol

library ModUtils {
    /// @dev Wraps the modular exponent pre-compile introduced in Byzantium.
    ///      Returns base^exponent mod p.
    function modExp(uint256 base, uint256 exponent, uint256 p) internal view returns (uint256 o) {
        assembly {
            // Args for the precompile: [<length_of_BASE> <length_of_EXPONENT>
            // <length_of_MODULUS> <BASE> <EXPONENT> <MODULUS>]
            let output := mload(0x40)
            let args := add(output, 0x20)
            mstore(args, 0x20)
            mstore(add(args, 0x20), 0x20)
            mstore(add(args, 0x40), 0x20)
            mstore(add(args, 0x60), base)
            mstore(add(args, 0x80), exponent)
            mstore(add(args, 0xa0), p)

            // 0x05 is the modular exponent contract address
            if iszero(staticcall(not(0), 0x05, args, 0xc0, output, 0x20)) { revert(0, 0) }
            o := mload(output)
        }
    }
}

/**
 * @title Compute Inverse by Modular Exponentiation
 *     @notice Compute $input^(N - 2) mod N$ using Addition Chain method.
 *     Where     N = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 *     and   N - 2 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
 *     @dev the function body is generated with the modified addchain script
 *     see https://github.com/kobigurk/addchain/commit/2c37a2ace567a9bdc680b4e929c94aaaa3ec700f
 *     Adapted from https://github.com/kobigurk/addchain/commit/2c37a2ace567a9bdc680b4e929c94aaaa3ec700f
 */
library ModexpInverse {
    function run(uint256 t2) internal pure returns (uint256 t0) {
        assembly {
            let n := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            t0 := mulmod(t2, t2, n)
            let t5 := mulmod(t0, t2, n)
            let t1 := mulmod(t5, t0, n)
            let t3 := mulmod(t5, t5, n)
            let t8 := mulmod(t1, t0, n)
            let t4 := mulmod(t3, t5, n)
            let t6 := mulmod(t3, t1, n)
            t0 := mulmod(t3, t3, n)
            let t7 := mulmod(t8, t3, n)
            t3 := mulmod(t4, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
        }
    }
}

/**
 * @title Compute Square Root by Modular Exponentiation
 *     @notice Compute $input^{(N + 1) / 4} mod N$ using Addition Chain method.
 *     Where           N = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 *     and   (N + 1) / 4 = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52
 */
library ModexpSqrt {
    function run(uint256 t6) internal pure returns (uint256 t0) {
        assembly {
            let n := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

            t0 := mulmod(t6, t6, n)
            let t4 := mulmod(t0, t6, n)
            let t2 := mulmod(t4, t0, n)
            let t3 := mulmod(t4, t4, n)
            let t8 := mulmod(t2, t0, n)
            let t1 := mulmod(t3, t4, n)
            let t5 := mulmod(t3, t2, n)
            t0 := mulmod(t3, t3, n)
            let t7 := mulmod(t8, t3, n)
            t3 := mulmod(t1, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t8, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t7, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t6, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t5, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t4, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t3, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t2, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t0, n)
            t0 := mulmod(t0, t1, n)
            t0 := mulmod(t0, t0, n)
        }
    }
}

// src/utils/CallWithExactGas.sol

/// @title CallWithExactGas contract
/// @notice Helper contract for making external calls within contracts with a specified gas amount.
abstract contract CallWithExactGas {
    /// @dev Gas required for exact EXTCODESIZE call and additional operations.
    uint256 internal constant GAS_FOR_CALL_EXACT_CHECK = 5_000;

    /// @dev Calls the target address with exactly `gasAmount` gas and provided `data` as calldata.
    /// @notice Reverts if at least `gasAmount` gas is not available.
    /// @param gasAmount The exact amount of gas to send with the call.
    /// @param target The address to call.
    /// @param data The calldata to send with the call.
    /// @return success A boolean indicating whether the call was successful.
    function _callWithExactGas(uint256 gasAmount, address target, bytes memory data) internal returns (bool success) {
        assembly {
            let g := gas()
            // Compute g -= GAS_FOR_CALL_EXACT_CHECK and check for underflow
            // The gas actually passed to the callee is min(gasAmount, 63//64*gas available).
            // We want to ensure that we revert if gasAmount >  63//64*gas available
            // as we do not want to provide them with less, however that check itself costs
            // gas.  GAS_FOR_CALL_EXACT_CHECK ensures we have at least enough gas to be able
            // to revert if gasAmount >  63//64*gas available.
            if lt(g, GAS_FOR_CALL_EXACT_CHECK) { revert(0, 0) }
            g := sub(g, GAS_FOR_CALL_EXACT_CHECK)
            // if g - g//64 <= gasAmount, revert
            // (we subtract g//64 because of EIP-150)
            if iszero(gt(sub(g, div(g, 64)), gasAmount)) { revert(0, 0) }
            // solidity calls check that a contract actually exists at the destination, so we do the same
            if iszero(extcodesize(target)) { revert(0, 0) }
            // call and return whether we succeeded. ignore return data
            // call(gas,addr,value,argsOffset,argsLength,retOffset,retLength)
            success := call(gasAmount, target, 0, add(data, 0x20), mload(data), 0, 0)
        }
        return success;
    }
}

// lib/openzeppelin-contracts/contracts/access/extensions/IAccessControlEnumerable.sol

// OpenZeppelin Contracts (last updated v5.1.0) (access/extensions/IAccessControlEnumerable.sol)

/**
 * @dev External interface of AccessControlEnumerable declared to support ERC-165 detection.
 */
interface IAccessControlEnumerable is IAccessControl {
    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
}

// lib/openzeppelin-contracts/contracts/utils/Address.sol

// OpenZeppelin Contracts (last updated v5.2.0) (utils/Address.sol)

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev There's no code at `target` (it is not a contract).
     */
    error AddressEmptyCode(address target);

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.20/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert Errors.InsufficientBalance(address(this).balance, amount);
        }

        (bool success, bytes memory returndata) = recipient.call{value: amount}("");
        if (!success) {
            _revert(returndata);
        }
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason or custom error, it is bubbled
     * up by this function (like regular Solidity function calls). However, if
     * the call reverted with no returned reason, this function reverts with a
     * {Errors.FailedCall} error.
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert Errors.InsufficientBalance(address(this).balance, value);
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and reverts if the target
     * was not a contract or bubbling up the revert reason (falling back to {Errors.FailedCall}) in case
     * of an unsuccessful call.
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and reverts if it wasn't, either by bubbling the
     * revert reason or with a default {Errors.FailedCall} error.
     */
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    /**
     * @dev Reverts with returndata if present. Otherwise reverts with {Errors.FailedCall}.
     */
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            assembly ("memory-safe") {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert Errors.FailedCall();
        }
    }
}

// lib/openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// src/libraries/BLS.sol

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Naehrig 254 bit curve (BN-254) used to verify BLS signaturess on the BN254 curve in Solidity
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We can use G1 points for signatures and messages, and G2 points for public keys or vice versa
/// @dev G1 is 64 bytes (uint256[2] in Solidity) and G2 is 128 bytes (uint256[4] in Solidity)
/// @dev Adapted from https://github.com/kevincharm/bls-bn254.git
library BLS {
    struct PointG1 {
        uint256 x;
        uint256 y;
    }

    struct PointG2 {
        uint256[2] x; // x coordinate (represented as 2 uint256 values) / Fp2 coordinates
        uint256[2] y; // y coordinate (represented as 2 uint256 values) / Fp2 coordinates
    }

    // GfP2 implements a field of size p² as a quadratic extension of the base field.
    struct GfP2 {
        uint256 x;
        uint256 y;
    }

    // Field order
    // p is a prime over which we form a basic field
    // go-ethereum/crypto/bn256/cloudflare/constants.go
    uint256 private constant N = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Generator of G1
    uint256 private constant G1_X = 1;
    uint256 private constant G1_Y = 2;

    // Negated generator of G1
    uint256 private constant N_G1_X = 1;
    uint256 private constant N_G1_Y = 21888242871839275222246405745257275088696311157297823662689037894645226208581;

    // Negated generator of G2
    uint256 private constant N_G2_X1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 private constant N_G2_X0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 private constant N_G2_Y1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 private constant N_G2_Y0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653;

    uint256 private constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 private constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice Param A of BN254
    uint256 private constant A = 0;
    /// @notice Param B of BN254
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 = 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 = 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    error BNAddFailed(uint256[4] input);
    error InvalidFieldElement(uint256 x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    /// @notice Computes the negation of a point on the G1 curve.
    /// @dev Returns the negation of the input point p on the elliptic curve.
    ///      If the point is at infinity (x = 0, y = 0), it returns the point
    ///      itself. Otherwise, it returns a new point with the same x-coordinate
    ///      and the negated y-coordinate modulo the curve's prime N.
    /// @param p The point on the G1 curve to negate.
    /// @return The negated point on the G1 curve, such that p + negate(p) = 0.
    function negate(PointG1 memory p) internal pure returns (PointG1 memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) {
            return PointG1(0, 0);
        } else {
            return PointG1(p.x, N - (p.y % N));
        }
    }

    /// @notice Adds two points on the G1 curve.
    /// @dev Uses the precompiled contract at address 0x06 to perform
    ///      elliptic curve point addition in the G1 group. This function
    ///      returns the resulting point r = p1 + p2.
    /// @dev Reverts if the point addition operation fails.
    /// @param p1 The first point on the G1 curve.
    /// @param p2 The second point on the G1 curve.
    /// @return r The resulting point from adding p1 and p2 on the G1 curve.
    function addG1Points(PointG1 memory p1, PointG1 memory p2) internal view returns (PointG1 memory r) {
        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }

        require(success, "G1 addition failed");
    }

    /// @notice Performs scalar multiplication of a point on the G1 curve.
    /// @dev Uses the precompiled contract at address 0x07 to perform
    ///      scalar multiplication of a point on the G1 curve, i.e.,
    ///      computes r = s * p, where s is the scalar and p is the point.
    /// @dev Reverts if the scalar multiplication operation fails.
    /// @param p The point on the G1 curve to be multiplied.
    /// @param s The scalar value to multiply the point by.
    /// @return r The resulting point from scalar multiplication, r = s * p.
    function scalarMulG1Point(PointG1 memory p, uint256 s) internal view returns (PointG1 memory r) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "G1 scalar multiplication failed");
    }

    /// @notice Compute a scalar multiplication with a scalar and the base point.
    function scalarMulG1Base(uint256 s) internal view returns (PointG1 memory r) {
        uint256[3] memory input;
        input[0] = G1_X;
        input[1] = G1_Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "G1 scalar multiplication failed");
    }

    /// @notice Verify signed message on g1 against signature on g1 and public key on g2
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingle(PointG1 memory signature, PointG2 memory pubkey, PointG1 memory message)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input = [
            signature.x,
            signature.y,
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0,
            message.x,
            message.y,
            pubkey.x[1],
            pubkey.x[0],
            pubkey.y[1],
            pubkey.y[0]
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Verifies that the same scalar is used in both rG1 and rG2.
    function verifyEqualityG1G2(PointG1 memory rG1, PointG2 memory rG2)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input =
            [rG1.x, rG1.y, N_G2_X1, N_G2_X0, N_G2_Y1, N_G2_Y0, G1_X, G1_Y, rG2.x[1], rG2.x[0], rG2.y[1], rG2.y[0]];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Verify signed message on g2 against signature on g2 and public key on g1
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingleG2(PointG2 memory signature, PointG1 memory pubkey, PointG2 memory message)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input = [
            N_G1_X,
            N_G1_Y,
            signature.x[1],
            signature.x[0],
            signature.y[1],
            signature.y[0],
            pubkey.x,
            pubkey.y,
            message.x[1],
            message.x[0],
            message.y[1],
            message.y[0]
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Hash to BN254 G1
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return point in G1
    function hashToPoint(bytes memory domain, bytes memory message) internal view returns (PointG1 memory point) {
        uint256[2] memory u = hashToField(domain, message);
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        if (!success) revert BNAddFailed(bnAddInput);
        point = PointG1({x: p0[0], y: p0[1]});
        return point;
    }

    /// @notice Check if point in g1 is a valid
    /// @param point The point on g1 to check
    function isValidPointG1(PointG1 memory point) internal pure returns (bool) {
        if ((point.x >= N) || (point.y >= N)) {
            return false;
        } else {
            return isOnCurveG1(point);
        }
    }

    /// @notice Check if point is a valid g2 point
    /// @param point the point to check
    function isValidPointG2(PointG2 memory point) internal pure returns (bool) {
        if ((point.x[0] >= N) || (point.x[1] >= N) || (point.y[0] >= N || (point.y[1] >= N))) {
            return false;
        } else {
            return isOnCurveG2(point);
        }
    }

    /// @notice Check if `point` is in G1
    /// @param p Point to check
    function isOnCurveG1(PointG1 memory p) internal pure returns (bool _isOnCurve) {
        uint256[2] memory point = [p.x, p.y];
        assembly {
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            let t2 := mulmod(t0, t0, N)
            t2 := mulmod(t2, t0, N)
            t2 := addmod(t2, 3, N)
            t1 := mulmod(t1, t1, N)
            _isOnCurve := eq(t1, t2)
        }
    }

    /// @notice Check if `point` is in G2
    /// @param p Point to check
    function isOnCurveG2(PointG2 memory p) internal pure returns (bool _isOnCurve) {
        uint256[4] memory point = [p.x[0], p.x[1], p.y[0], p.y[1]];
        assembly {
            // x0, x1
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            // x0 ^ 2
            let t2 := mulmod(t0, t0, N)
            // x1 ^ 2
            let t3 := mulmod(t1, t1, N)
            // 3 * x0 ^ 2
            let t4 := add(add(t2, t2), t2)
            // 3 * x1 ^ 2
            let t5 := addmod(add(t3, t3), t3, N)
            // x0 * (x0 ^ 2 - 3 * x1 ^ 2)
            t2 := mulmod(add(t2, sub(N, t5)), t0, N)
            // x1 * (3 * x0 ^ 2 - x1 ^ 2)
            t3 := mulmod(add(t4, sub(N, t3)), t1, N)

            // x ^ 3 + b
            t0 := addmod(t2, 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5, N)
            t1 := addmod(t3, 0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2, N)

            // y0, y1
            t2 := mload(add(point, 64))
            t3 := mload(add(point, 96))
            // y ^ 2
            t4 := mulmod(addmod(t2, t3, N), addmod(t2, sub(N, t3), N), N)
            t3 := mulmod(shl(1, t2), t3, N)

            // y ^ 2 == x ^ 3 + b
            _isOnCurve := and(eq(t0, t4), eq(t1, t3))
        }
    }

    /// @notice Unmarshals a point on G1 from bytes in an uncompressed form.
    function g1Unmarshal(bytes memory m) internal pure returns (PointG1 memory) {
        require(m.length == 64, "Invalid G1 bytes length");

        bytes32 x;
        bytes32 y;

        assembly {
            x := mload(add(m, 0x20))
            y := mload(add(m, 0x40))
        }

        return PointG1(uint256(x), uint256(y));
    }

    /// @notice Marshals a point on G1 to bytes form.
    function g1Marshal(PointG1 memory point) internal pure returns (bytes memory) {
        bytes memory m = new bytes(64);
        bytes32 x = bytes32(point.x);
        bytes32 y = bytes32(point.y);

        assembly {
            mstore(add(m, 32), x)
            mstore(add(m, 64), y)
        }

        return m;
    }

    /// @dev Unmarshals a point on G2 from bytes in an uncompressed form.
    function g2Unmarshal(bytes memory m) internal pure returns (PointG2 memory) {
        require(m.length == 128, "Invalid G2 bytes length");

        uint256 xx;
        uint256 xy;
        uint256 yx;
        uint256 yy;

        assembly {
            xx := mload(add(m, 0x20))
            xy := mload(add(m, 0x40))
            yx := mload(add(m, 0x60))
            yy := mload(add(m, 0x80))
        }

        return PointG2([xx, xy], [yx, yy]);
    }

    function g2Marshal(PointG2 memory point) internal pure returns (bytes memory) {
        bytes memory m = new bytes(128);
        bytes32 xx = bytes32(point.x[0]);
        bytes32 xy = bytes32(point.x[1]);
        bytes32 yx = bytes32(point.y[0]);
        bytes32 yy = bytes32(point.y[1]);

        assembly {
            mstore(add(m, 0x20), xx)
            mstore(add(m, 0x40), xy)
            mstore(add(m, 0x60), yx)
            mstore(add(m, 0x80), yy)
        }

        return m;
    }

    /// @notice sqrt(xx) mod N
    /// @param xx Input
    function sqrt(uint256 xx) internal pure returns (uint256 x, bool hasRoot) {
        x = ModexpSqrt.run(xx);
        hasRoot = mulmod(x, x, N) == xx;
    }

    /// @notice a^{-1} mod N
    /// @param a Input
    function inverse(uint256 a) internal pure returns (uint256) {
        return ModexpInverse.run(a);
    }

    /// @notice Hash a message to the field
    /// @param domain Domain separation tag
    /// @param message Message to hash
    function hashToField(bytes memory domain, bytes memory message) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsgTo96(domain, message);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return [a0, a1];
    }

    function hashToFieldSingle(bytes memory domain, bytes memory message) internal pure returns (uint256) {
        bytes memory _msg = expandMsg(domain, message, 48);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return a0;
    }

    /// @notice Expand arbitrary message to n bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param DST Domain separation tagimport {console} from "forge-std/console.sol";

    /// @param message Message to expand
    function expandMsg(bytes memory DST, bytes memory message, uint8 n_bytes) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(zpad, message, uint8(0), n_bytes, uint8(0), DST, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), DST, uint8(domainLen));
        bytes32 bi = keccak256(b_i);
        bytes memory out = new bytes(n_bytes);
        uint256 ell = (n_bytes + uint256(31)) >> 5;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), DST, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Expand arbitrary message to 96 pseudorandom bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param DST Domain separation tag
    /// @param message Message to expand
    function expandMsgTo96(bytes memory DST, bytes memory message) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(zpad, message, uint8(0), uint8(96), uint8(0), DST, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), DST, uint8(domainLen));
        bytes32 bi = keccak256(b_i);

        bytes memory out = new bytes(96);
        uint256 ell = 3;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), DST, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(uint256 u) internal view returns (uint256[2] memory p) {
        if (u >= N) revert InvalidFieldElement(u);

        uint256 tv1 = mulmod(mulmod(u, u, N), C1, N);
        uint256 tv2 = addmod(1, tv1, N);
        tv1 = addmod(1, N - tv1, N);
        uint256 tv3 = inverse(mulmod(tv1, tv2, N));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, N), tv3, N), C3, N);
        uint256 x1 = addmod(C2, N - tv5, N);
        uint256 x2 = addmod(C2, tv5, N);
        uint256 tv7 = mulmod(tv2, tv2, N);
        uint256 tv8 = mulmod(tv7, tv3, N);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, N), N), N);

        bool hasRoot;
        uint256 gx;
        if (legendre(g(x1)) == 1) {
            p[0] = x1;
            gx = g(x1);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else if (legendre(g(x2)) == 1) {
            p[0] = x2;
            gx = g(x2);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else {
            p[0] = x3;
            gx = g(x3);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = N - p[1];
        }
    }

    /// @notice g(x) = y^2 = x^3 + 3
    function g(uint256 x) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, N), x, N), B, N);
    }

    /// @notice https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    function sgn0(uint256 x) private pure returns (uint256) {
        return x % 2;
    }

    /// @notice Compute Legendre symbol of u
    /// @param u Field element
    /// @return 1 if u is a quadratic residue, -1 if not, or 0 if u = 0 (mod p)
    function legendre(uint256 u) private view returns (int8) {
        uint256 x = modexpLegendre(u);
        if (x == N - 1) {
            return -1;
        }
        if (x != 0 && x != 1) {
            revert MapToPointFailed(u);
        }
        return int8(int256(x));
    }

    /// @notice This is cheaper than an addchain for exponent (N-1)/2
    function modexpLegendre(uint256 u) private view returns (uint256 output) {
        bytes memory input = new bytes(192);
        bool success;
        assembly {
            let p := add(input, 32)
            mstore(p, 32) // len(u)
            p := add(p, 32)
            mstore(p, 32) // len(exp)
            p := add(p, 32)
            mstore(p, 32) // len(mod)
            p := add(p, 32)
            mstore(p, u) // u
            p := add(p, 32)
            mstore(p, C5) // (N-1)/2
            p := add(p, 32)
            mstore(p, N) // N

            success :=
                staticcall(
                    gas(),
                    5,
                    add(input, 32),
                    192,
                    0x00, // scratch space <- result
                    32
                )
            output := mload(0x00) // output <- result
        }
        if (!success) {
            revert ModExpFailed(u, C5, N);
        }
    }
}

// lib/openzeppelin-contracts-upgradeable/contracts/utils/introspection/ERC165Upgradeable.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/introspection/ERC165.sol)

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165Upgradeable is Initializable, IERC165 {
    function __ERC165_init() internal onlyInitializing {
    }

    function __ERC165_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// src/libraries/TypesLib.sol

/// @title TypesLib
/// @author Randamu
/// @notice Library declaring custom data types used for randomness and blocklock requests
library TypesLib {
    /// @notice  Ciphertext representing data encrypted off-chain
    struct Ciphertext {
        BLS.PointG2 u;
        bytes v;
        bytes w;
    }

    /// @notice  BlocklockRequest stores details needed to generate blocklock decryption keys
    struct BlocklockRequest {
        uint256 subId; // must be 0 for direct funding
        uint256 directFundingFeePaid; // must be > 0 for direct funding and if subId == 0
        uint64 decryptionRequestID;
        uint256 blockHeight;
        Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
        address callback;
    }

    /// @notice  DecryptionRequest stores details for each decryption request
    struct DecryptionRequest {
        string schemeID;
        bytes ciphertext;
        bytes condition;
        bytes decryptionKey;
        bytes signature;
        address callback;
        // used by offchain agent / oracle for callback gasLimit
        // should cover costs for callbacks from decryptionSender to consumer contract via blocklockSender
        uint32 callbackGasLimit;
        bool isFulfilled;
    }
}

// src/interfaces/IDecryptionReceiver.sol

/// @title IDecryptionReceiver interface
/// @author Randamu
/// @notice Interface for smart contract that recieives decryption key and associated
/// signature for user conditional decryption requests.
interface IDecryptionReceiver {
    /// @notice Receives a decryption key that can be used to decrypt the ciphertext
    /// @dev This function is intended to be called by an authorized decrypter contract
    /// @param requestID The ID of the request for which the decryption key is provided
    /// @param decryptionKey The decryption key associated with the request, provided as a byte array
    /// @param signature The signature associated with the request, provided as a byte array
    function receiveDecryptionData(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external;
}

// src/interfaces/IDecryptionSender.sol

/// @title IDecryptionSender interface
/// @author Randamu
/// @notice Interface for smart contract that stores and conditionally decrypts encrypted messages / data
interface IDecryptionSender {
    /// @notice Registers a Ciphertext and associated condition for decryption
    /// @notice creation of the `Ciphertext` and `condition` bytes will be managed by a javascript client library off-chain
    /// @dev The creation of `Ciphertext` and `condition` bytes will be managed by the JavaScript client library
    /// @param ciphertext The encrypted data to be registered
    /// @param callbackGasLimit The gas limit for the callback.
    /// @param condition The condition that need to be met to decrypt the ciphertext
    /// @return requestID The unique ID assigned to the registered decryption request
    function registerCiphertext(
        string calldata schemeID,
        uint32 callbackGasLimit,
        bytes calldata ciphertext,
        bytes calldata condition
    ) external returns (uint256 requestID);

    /// @notice Provide the decryption key for a specific requestID alongside a signature.
    /// @dev This function is intended to be called after a decryption key has been generated off-chain.
    /// @param requestID The unique identifier for the encryption request. This should match the ID used
    ///                  when the encryption was initially requested.
    /// @param decryptionKey The decrypted content in bytes format. The data should represent the original
    ///                      message in its decrypted form.
    /// @param signature The signature associated with the request, provided as a byte array
    function fulfillDecryptionRequest(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external;

    /// @notice Updates the signature scheme address provider contract address
    /// @param newSignatureSchemeAddressProvider The signature address provider address to set
    ////
    function setSignatureSchemeAddressProvider(address newSignatureSchemeAddressProvider) external;

    /// @notice Retrieves a specific request by its ID.
    /// @dev This function returns the Request struct associated with the given requestId.
    /// @param requestId The ID of the request to retrieve.
    /// @return The Request struct corresponding to the given requestId.
    function getRequest(uint256 requestId) external view returns (TypesLib.DecryptionRequest memory);

    /// @notice Verifies whether a specific request is in flight or not.
    /// @param requestID The ID of the request to check.
    /// @return boolean indicating whether the request is in flight or not.
    function isInFlight(uint256 requestID) external view returns (bool);

    /// @notice returns whether a specific request errored during callback or not.
    /// @param requestID The ID of the request to check.
    /// @return boolean indicating whether the request has errored or not.
    function hasPaymentErrored(uint256 requestID) external view returns (bool);

    /// @notice Returns all the fulfilled request ids.
    /// @return The uint array representing a set containing all fulfilled request ids.
    function getAllFulfilledRequestIds() external view returns (uint256[] memory);

    /// @notice Returns all the request ids that are yet to be fulfilled.
    /// @return The uint array representing a set containing all request ids that are yet to be fulfilled.
    function getAllUnfulfilledRequestIds() external view returns (uint256[] memory);

    /// @notice Returns all the request ids where the callback reverted but a decryption key was provided, i.e., "fulfilled" but still in flight.
    /// @return The uint array representing a set containing all request ids with reverting callbacks.
    function getAllpaymentErroredRequestIds() external view returns (uint256[] memory);

    /// @notice Returns count of all the request ids that are yet to be fulfilled.
    /// @return A uint representing a count of all request ids that are yet to be fulfilled.
    function getCountOfUnfulfilledRequestIds() external view returns (uint256);

    /// @dev Returns the version number of the upgradeable contract.
    function version() external pure returns (string memory);
}

// src/subscription/SubscriptionAPI.sol

/// @title Subscription API contract
/// @notice Abstract contract for managing user subscription accounts for onchain services.
/// @notice Minimal version of Chainlinks SubscriptionAPI contract.
/// @notice Available at https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/vrf/dev/SubscriptionAPI.sol
/// @notice License: MIT
abstract contract SubscriptionAPI is ReentrancyGuard, ISubscription {
    using EnumerableSet for EnumerableSet.UintSet;

    // We need to maintain a list of consuming addresses.
    // This bound ensures we are able to loop over them as needed.
    // Should a user require more consumers, they can use multiple subscriptions.
    uint16 public constant MAX_CONSUMERS = 100;

    error TooManyConsumers();
    error InsufficientBalance();
    error InvalidConsumer(uint256 subId, address consumer);
    error InvalidSubscription();
    error InvalidCalldata();
    error MustBeSubOwner(address owner);
    error MustBeRequestedOwner(address proposedOwner);
    error BalanceInvariantViolated(uint256 internalBalance, uint256 externalBalance); // Should never happen
    error FailedToSendNative();
    error IndexOutOfRange();
    error PendingRequestExists();

    // We use the subscription struct (1 word)
    // at fulfillment time.
    struct Subscription {
        // a uint96 is large enough to hold around ~8e28 wei, or 80 billion ether.
        // That should be enough to cover most (if not all) subscriptions.
        uint96 nativeBalance; // Common native balance used for all consumer requests.
        uint64 reqCount;
    }
    // We use the config for the mgmt APIs

    struct SubscriptionConfig {
        address owner; // Owner can fund/withdraw/cancel the sub.
        address requestedOwner; // For safely transferring sub ownership.
        // Maintains the list of keys in s_consumers.
        // We do this for 2 reasons:
        // 1. To be able to clean up all keys from s_consumers when canceling a subscription.
        // 2. To be able to return the list of all consumers in getSubscription.
        // Note that we need the s_consumers map to be able to directly check if a
        // consumer is valid without reading all the consumers from storage.
        address[] consumers;
    }

    struct ConsumerConfig {
        bool active;
        uint64 nonce;
        uint64 pendingReqCount;
    }
    // Note a nonce of 0 indicates the consumer is not assigned to that subscription.

    mapping(address => mapping(uint256 => ConsumerConfig)) /* consumerAddress */ /* subId */ /* consumerConfig */
        internal s_consumers;
    mapping(uint256 => SubscriptionConfig) /* subId */ /* subscriptionConfig */ internal s_subscriptionConfigs;
    mapping(uint256 => Subscription) /* subId */ /* subscription */ internal s_subscriptions;
    // subscription nonce used to construct subId. Rises monotonically
    uint64 public s_currentSubNonce;
    // track all subscription id's that were created by this contract
    // note: access should be through the getActiveSubscriptionIds() view function
    // which takes a starting index and a max number to fetch in order to allow
    // "pagination" of the subscription ids. in the event a very large number of
    // subscription id's are stored in this set, they cannot be retrieved in a
    // single RPC call without violating various size limits.
    EnumerableSet.UintSet internal s_subIds;
    // s_totalNativeBalance tracks the total native sent to/from
    // this contract through fundSubscription, cancelSubscription.
    // A discrepancy with this contract's native balance indicates someone
    // sent native using transfer and so we may need to use recoverNativeFunds.
    uint96 public s_totalNativeBalance;
    // The following variables track fees collected from direct funding requests or
    // subscription based requests that have become withdrawable for contract admin.
    uint96 public s_withdrawableDirectFundingFeeNative;
    uint96 public s_withdrawableSubscriptionFeeNative;

    event SubscriptionCreated(uint256 indexed subId, address owner);
    event SubscriptionFundedWithNative(uint256 indexed subId, uint256 oldNativeBalance, uint256 newNativeBalance);
    event SubscriptionConsumerAdded(uint256 indexed subId, address consumer);
    event SubscriptionConsumerRemoved(uint256 indexed subId, address consumer);
    event SubscriptionCanceled(uint256 indexed subId, address to, uint256 amountNative);
    event SubscriptionOwnerTransferRequested(uint256 indexed subId, address from, address to);
    event SubscriptionOwnerTransferred(uint256 indexed subId, address from, address to);

    struct Config {
        uint32 maxGasLimit;
        // Gas to cover oracle payment after we calculate the payment.
        // We make it configurable in case those operations are repriced.
        // The recommended number is below, though it may vary slightly
        // if certain chains do not implement certain EIP's.
        // 21000 + // base cost of the transaction
        // 100 + 5000 + // warm subscription balance read and update. See https://eips.ethereum.org/EIPS/eip-2929
        // 2*2100 + 5000 - // cold read oracle address and oracle balance and first time oracle balance update, note first time will be 20k, but 5k subsequently
        // 4800 + // request delete refund (refunds happen after execution), note pre-london fork was 15k. See https://eips.ethereum.org/EIPS/eip-3529
        // 6685 + // Positive static costs of argument encoding etc. note that it varies by +/- x*12 for every x bytes of non-zero data in the proof.
        // Total: 37,185 gas.
        uint32 gasAfterPaymentCalculation;
        // Flat fee charged per fulfillment in millionths of native.
        // So fee range is [0, 2^32/10^6].
        uint32 fulfillmentFlatFeeNativePPM;
        // Wei charged per unit of gas for callback operations
        uint32 weiPerUnitGas;
        uint32 blsPairingCheckOverhead;
        // nativePremiumPercentage is the percentage of the total gas costs that is added to the final premium for native payment
        // nativePremiumPercentage = 10 means 10% of the total gas costs is added. only integral percentage is allowed
        uint8 nativePremiumPercentage;
    }

    Config public s_config;

    modifier onlySubOwner(uint256 subId) {
        _onlySubOwner(subId);
        _;
    }

    function _requireSufficientBalance(bool condition) internal pure {
        if (!condition) {
            revert InsufficientBalance();
        }
    }

    function _requireValidSubscription(address subOwner) internal pure {
        if (subOwner == address(0)) {
            revert InvalidSubscription();
        }
    }

    /**
     * @inheritdoc ISubscription
     */
    function fundSubscriptionWithNative(uint256 subId) external payable override nonReentrant {
        _requireValidSubscription(s_subscriptionConfigs[subId].owner);
        // We do not check that the msg.sender is the subscription owner,
        // anyone can fund a subscription.
        // We also do not check that msg.value > 0, since that's just a no-op
        // and would be a waste of gas on the caller's part.
        uint256 oldNativeBalance = s_subscriptions[subId].nativeBalance;
        s_subscriptions[subId].nativeBalance += uint96(msg.value);
        s_totalNativeBalance += uint96(msg.value);
        emit SubscriptionFundedWithNative(subId, oldNativeBalance, oldNativeBalance + msg.value);
    }

    /**
     * @inheritdoc ISubscription
     */
    function getSubscription(uint256 subId)
        public
        view
        override
        returns (uint96 nativeBalance, uint64 reqCount, address subOwner, address[] memory consumers)
    {
        subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        return (
            s_subscriptions[subId].nativeBalance,
            s_subscriptions[subId].reqCount,
            subOwner,
            s_subscriptionConfigs[subId].consumers
        );
    }

    /**
     * @inheritdoc ISubscription
     */
    function getActiveSubscriptionIds(uint256 startIndex, uint256 maxCount)
        external
        view
        override
        returns (uint256[] memory ids)
    {
        uint256 numSubs = s_subIds.length();
        if (startIndex >= numSubs) revert IndexOutOfRange();
        uint256 endIndex = startIndex + maxCount;
        endIndex = endIndex > numSubs || maxCount == 0 ? numSubs : endIndex;
        uint256 idsLength = endIndex - startIndex;
        ids = new uint256[](idsLength);
        for (uint256 idx = 0; idx < idsLength; ++idx) {
            ids[idx] = s_subIds.at(idx + startIndex);
        }
        return ids;
    }

    /**
     * @inheritdoc ISubscription
     */
    function createSubscription() external override nonReentrant returns (uint256 subId) {
        // Generate a subscription id that is globally unique.
        uint64 currentSubNonce = s_currentSubNonce;
        subId = uint256(
            keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1), address(this), currentSubNonce))
        );
        // Increment the subscription nonce counter.
        s_currentSubNonce = currentSubNonce + 1;
        // Initialize storage variables.
        address[] memory consumers = new address[](0);
        s_subscriptions[subId] = Subscription({nativeBalance: 0, reqCount: 0});
        s_subscriptionConfigs[subId] =
            SubscriptionConfig({owner: msg.sender, requestedOwner: address(0), consumers: consumers});
        // Update the s_subIds set, which tracks all subscription ids created in this contract.
        s_subIds.add(subId);

        emit SubscriptionCreated(subId, msg.sender);
    }

    /// @notice Checks if there are any pending decryption requests for a given subscription.
    /// @dev Iterates through all consumers of the subscription to check for pending requests.
    /// @param subId The subscription ID to check for pending requests.
    /// @return True if at least one consumer has a pending request, otherwise false.
    function pendingRequestExists(uint256 subId) public view override returns (bool) {
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        uint256 consumersLength = consumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            if (s_consumers[consumers[i]][subId].pendingReqCount > 0) {
                return true;
            }
        }
        return false;
    }

    /// @notice Cancels a subscription and sends remaining funds to the specified address.
    /// @dev Ensures there are no pending decryption requests before cancellation.
    ///      Only the subscription owner can call this function.
    /// @param subId The subscription ID to cancel.
    /// @param to The address where remaining funds should be sent.
    /// @custom:error PendingRequestExists Thrown if there are pending decryption requests for the subscription.
    function cancelSubscription(uint256 subId, address to) external override onlySubOwner(subId) nonReentrant {
        if (pendingRequestExists(subId)) {
            revert PendingRequestExists();
        }
        _cancelSubscriptionHelper(subId, to);
    }

    /// @notice Removes a consumer from a subscription.
    /// @dev Only the subscription owner can call this function.
    ///      Ensures there are no pending requests before removing the consumer.
    ///      The consumer is removed by swapping with the last element in the array and then popping.
    /// @param subId The subscription ID from which the consumer will be removed.
    /// @param consumer The address of the consumer to remove.
    /// @custom:error PendingRequestExists Thrown if there are pending decryption requests for the subscription.
    /// @custom:error InvalidConsumer Thrown if the consumer is not active under the subscription.
    /// @custom:event SubscriptionConsumerRemoved Emitted when a consumer is successfully removed.
    function removeConsumer(uint256 subId, address consumer) external override onlySubOwner(subId) nonReentrant {
        if (pendingRequestExists(subId)) {
            revert PendingRequestExists();
        }
        if (!s_consumers[consumer][subId].active) {
            revert InvalidConsumer(subId, consumer);
        }

        // Remove consumer from subscription list
        address[] storage s_subscriptionConsumers = s_subscriptionConfigs[subId].consumers;
        uint256 consumersLength = s_subscriptionConsumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            if (s_subscriptionConsumers[i] == consumer) {
                s_subscriptionConsumers[i] = s_subscriptionConsumers[consumersLength - 1]; // Swap with last element
                s_subscriptionConsumers.pop(); // Remove last element
                break;
            }
        }

        s_consumers[consumer][subId].active = false;
        emit SubscriptionConsumerRemoved(subId, consumer);
    }

    /**
     * @inheritdoc ISubscription
     */
    function requestSubscriptionOwnerTransfer(uint256 subId, address newOwner)
        external
        override
        onlySubOwner(subId)
        nonReentrant
    {
        // Proposing to address(0) would never be claimable so don't need to check.
        SubscriptionConfig storage subscriptionConfig = s_subscriptionConfigs[subId];
        if (subscriptionConfig.requestedOwner != newOwner) {
            subscriptionConfig.requestedOwner = newOwner;
            emit SubscriptionOwnerTransferRequested(subId, msg.sender, newOwner);
        }
    }

    /**
     * @inheritdoc ISubscription
     */
    function acceptSubscriptionOwnerTransfer(uint256 subId) external override nonReentrant {
        address oldOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(oldOwner);
        if (s_subscriptionConfigs[subId].requestedOwner != msg.sender) {
            revert MustBeRequestedOwner(s_subscriptionConfigs[subId].requestedOwner);
        }
        s_subscriptionConfigs[subId].owner = msg.sender;
        s_subscriptionConfigs[subId].requestedOwner = address(0);
        emit SubscriptionOwnerTransferred(subId, oldOwner, msg.sender);
    }

    /**
     * @inheritdoc ISubscription
     */
    function addConsumer(uint256 subId, address consumer) external override onlySubOwner(subId) nonReentrant {
        ConsumerConfig storage consumerConfig = s_consumers[consumer][subId];
        if (consumerConfig.active) {
            // Idempotence - do nothing if already added.
            // Ensures uniqueness in s_subscriptions[subId].consumers.
            return;
        }
        // Already maxed, cannot add any more consumers.
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        if (consumers.length == MAX_CONSUMERS) {
            revert TooManyConsumers();
        }
        // consumerConfig.nonce is 0 if the consumer had never sent a request to this subscription
        // otherwise, consumerConfig.nonce is non-zero
        // in both cases, use consumerConfig.nonce as is and set active status to true
        consumerConfig.active = true;
        consumers.push(consumer);

        emit SubscriptionConsumerAdded(subId, consumer);
    }

    function _deleteSubscription(uint256 subId) internal returns (uint96 nativeBalance) {
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        nativeBalance = s_subscriptions[subId].nativeBalance;
        // Note bounded by MAX_CONSUMERS;
        // If no consumers, does nothing.
        uint256 consumersLength = consumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            delete s_consumers[consumers[i]][subId];
        }
        delete s_subscriptionConfigs[subId];
        delete s_subscriptions[subId];
        s_subIds.remove(subId);
        if (nativeBalance != 0) {
            s_totalNativeBalance -= nativeBalance;
        }
    }

    function _cancelSubscriptionHelper(uint256 subId, address to) internal {
        (uint96 nativeBalance) = _deleteSubscription(subId);

        // send native to the "to" address using call
        _mustSendNative(to, uint256(nativeBalance));
        emit SubscriptionCanceled(subId, to, nativeBalance);
    }

    function _onlySubOwner(uint256 subId) internal view {
        address subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        if (msg.sender != subOwner) {
            revert MustBeSubOwner(subOwner);
        }
    }

    function _mustSendNative(address to, uint256 amount) internal {
        (bool success,) = to.call{value: amount}("");
        if (!success) {
            revert FailedToSendNative();
        }
    }
}

// src/interfaces/IBlocklockSender.sol

/// @title IBlocklockSender interface
/// @author Randamu
/// @notice Interface for periphery smart contract used to interact with the decryption sender contract.
interface IBlocklockSender is ISubscription {
    /// @notice Requests the generation of a blocklock decryption key at a specific blockHeight.
    /// @dev Initiates a blocklock decryption key request.
    /// The blocklock decryption key will be generated once the chain reaches the specified `blockHeight`.
    /// @return requestID The unique identifier assigned to this blocklock request.
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable returns (uint256 requestID);

    /// @notice Requests a blocklock for a specified block height with the provided ciphertext without a subscription ID.
    /// Requires payment to be made for the request without a subscription.
    /// @param callbackGasLimit The gas limit allocated for the callback execution after the blocklock request
    /// @param blockHeight The block height at which the blocklock is requested
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @return requestID The unique identifier for the blocklock request
    /// @dev This function allows users to request a blocklock for a specific block height. The blocklock is not associated with any subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is configured and not disabled before processing the request.
    function requestBlocklock(uint32 callbackGasLimit, uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        external
        payable
        returns (uint256 requestID);

    /// @notice Calculates the estimated price in native tokens for a request based on the provided gas limit
    /// @param _callbackGasLimit The gas limit for the callback execution
    /// @return The estimated request price in native token (e.g., ETH)
    function calculateRequestPriceNative(uint32 _callbackGasLimit) external view returns (uint256);

    /// @notice Estimates the request price in native tokens using a specified gas price
    /// @param _callbackGasLimit The gas limit for the callback execution
    /// @param _requestGasPriceWei The gas price (in wei) to use for the estimation
    /// @return The estimated total request price in native token (e.g., ETH)
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        returns (uint256);

    /// @notice Updates the decryptionn sender contract address
    /// @param newDecryptionSender The decryption sender address to set
    function setDecryptionSender(address newDecryptionSender) external;

    /// @notice Retrieves a specific request by its ID.
    /// @dev This function returns the Request struct associated with the given requestId.
    /// @param requestId The ID of the request to retrieve.
    /// @return The Request struct corresponding to the given requestId.
    function getRequest(uint256 requestId) external view returns (TypesLib.BlocklockRequest memory);

    /// Decrypt a ciphertext into a plaintext using a decryption key.
    /// @param ciphertext The ciphertext to decrypt.
    /// @param decryptionKey The decryption key that can be used to decrypt the ciphertext.
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        external
        view
        returns (bytes memory);

    /// @dev Returns the version number of the upgradeable contract.
    function version() external pure returns (string memory);

    /// @notice Returns the current blockchain chain ID.
    /// @dev Uses inline assembly to retrieve the `chainid` opcode.
    /// @return chainId The current chain ID of the network.
    function getChainId() external view returns (uint256 chainId);
}

// lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol

// OpenZeppelin Contracts (last updated v5.2.0) (proxy/ERC1967/ERC1967Utils.sol)

/**
 * @dev This library provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[ERC-1967] slots.
 */
library ERC1967Utils {
    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev The `implementation` of the proxy is invalid.
     */
    error ERC1967InvalidImplementation(address implementation);

    /**
     * @dev The `admin` of the proxy is invalid.
     */
    error ERC1967InvalidAdmin(address admin);

    /**
     * @dev The `beacon` of the proxy is invalid.
     */
    error ERC1967InvalidBeacon(address beacon);

    /**
     * @dev An upgrade function sees `msg.value > 0` that may be lost.
     */
    error ERC1967NonPayable();

    /**
     * @dev Returns the current implementation address.
     */
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the ERC-1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Performs implementation upgrade with additional setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit IERC1967.Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by ERC-1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
     */
    function getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the ERC-1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        if (newAdmin == address(0)) {
            revert ERC1967InvalidAdmin(address(0));
        }
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {IERC1967-AdminChanged} event.
     */
    function changeAdmin(address newAdmin) internal {
        emit IERC1967.AdminChanged(getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is the keccak-256 hash of "eip1967.proxy.beacon" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the ERC-1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        if (newBeacon.code.length == 0) {
            revert ERC1967InvalidBeacon(newBeacon);
        }

        StorageSlot.getAddressSlot(BEACON_SLOT).value = newBeacon;

        address beaconImplementation = IBeacon(newBeacon).implementation();
        if (beaconImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(beaconImplementation);
        }
    }

    /**
     * @dev Change the beacon and trigger a setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-BeaconUpgraded} event.
     *
     * CAUTION: Invoking this function has no effect on an instance of {BeaconProxy} since v5, since
     * it uses an immutable beacon without looking at the value of the ERC-1967 beacon slot for
     * efficiency.
     */
    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        _setBeacon(newBeacon);
        emit IERC1967.BeaconUpgraded(newBeacon);

        if (data.length > 0) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value` stuck in the contract
     * if an upgrade doesn't perform an initialization call.
     */
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}

// lib/openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.0.0) (access/AccessControl.sol)

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControlUpgradeable is Initializable, ContextUpgradeable, IAccessControl, ERC165Upgradeable {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /// @custom:storage-location erc7201:openzeppelin.storage.AccessControl
    struct AccessControlStorage {
        mapping(bytes32 role => RoleData) _roles;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControl")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlStorageLocation = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    function _getAccessControlStorage() private pure returns (AccessControlStorage storage $) {
        assembly {
            $.slot := AccessControlStorageLocation
        }
    }

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    function __AccessControl_init() internal onlyInitializing {
    }

    function __AccessControl_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        return $._roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        return $._roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        AccessControlStorage storage $ = _getAccessControlStorage();
        bytes32 previousAdminRole = getRoleAdmin(role);
        $._roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        if (!hasRole(role, account)) {
            $._roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        if (hasRole(role, account)) {
            $._roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

// src/blocklock/BlocklockFeeCollector.sol

/// @title BlocklockFeeCollector contract
/// @notice An abstract contract for collecting fees related to blocklock functionality
/// @dev This contract is intended to be inherited by other contracts that need to collect fees.
/// @dev The contract includes functionality from CallWithExactGas, ReentrancyGuard, and SubscriptionAPI.
/// @dev Inspired by Chainlink's VRFV2PlusWrapper contract at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/vrf/dev/VRFV2PlusWrapper.sol
/// @notice License: MIT
abstract contract BlocklockFeeCollector is CallWithExactGas, ReentrancyGuard, SubscriptionAPI {
    /// @dev Upper bound for premium percentages to prevent overflow in fee calculations.
    uint8 internal constant PREMIUM_PERCENTAGE_MAX = 155;

    /// @dev Tracks whether the contract has been configured (required for requests).
    bool public s_configured;

    /// @dev Disables the contract when true. Existing requests can still be fulfilled.
    bool public s_disabled;

    /// @dev Emitted when the contract is enabled.
    event Enabled();

    /// @dev Emitted when the contract is disabled.
    event Disabled();

    /// @dev Emitted for L1 gas fee tracking.
    event L1GasFee(uint256 fee);

    /// @dev Emitted when the contract configuration is updated.
    event ConfigSet(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage
    );

    /// @dev Ensures function is only called when the contract configuration parameters are set and
    /// the contract is not disabled.
    modifier onlyConfiguredNotDisabled() {
        require(s_configured, "Contract is not configured");
        require(!s_disabled, "Contract is disabled");
        _;
    }

    /// @notice Disables the functionality of the contract, preventing further actions
    /// @dev Can be overridden in derived contracts to implement specific disable behavior
    function disable() external virtual {}

    /// @notice Enables the functionality of the contract, allowing further actions
    /// @dev Can be overridden in derived contracts to implement specific enable behavior
    function enable() external virtual {}

    /// @notice Cancels the subscription for the given subscription ID
    /// @param subId The ID of the subscription to cancel
    /// @dev Can be overridden in derived contracts to implement specific cancellation logic
    function ownerCancelSubscription(uint256 subId) external virtual {}

    /// @notice Withdraws native tokens from the contract to the specified recipient address
    /// @param recipient The address to send the withdrawn funds to
    /// @dev The recipient must be a valid address that can receive native tokens
    function withdrawSubscriptionFeesNative(address payable recipient) external virtual {}

    function withdrawDirectFundingFeesNative(address payable recipient) external virtual {}

    /// @notice Configures the contract's settings.
    /// @dev This function sets the global gas limit, post-fulfillment gas usage, and fee structure.
    ///      Can only be called by an admin.
    /// @param maxGasLimit The maximum gas allowed for a request.
    /// @param gasAfterPaymentCalculation The gas required for post-fulfillment accounting.
    /// @param fulfillmentFlatFeeNativePPM The flat fee (in parts-per-million) for native token payments.
    /// @param nativePremiumPercentage The percentage-based premium for native payments.
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage
    ) external virtual {}

    /// @notice Calculates the price of a request with the given callbackGasLimit at the current
    /// @notice block.
    /// @dev This function relies on the transaction gas price which is not automatically set during
    /// @dev simulation. To estimate the price at a specific gas price, use the estimatePrice function.
    /// @param _callbackGasLimit is the gas limit used to estimate the price.
    function calculateRequestPriceNative(uint32 _callbackGasLimit) public view virtual returns (uint256) {
        return _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
    }

    /// @notice Estimates the price of a request with a specific gas limit and gas price.
    /// @dev This is a convenience function that can be called in simulation to better understand
    /// @dev pricing.
    /// @param _callbackGasLimit is the gas limit used to estimate the price.
    /// @param _requestGasPriceWei is the gas price in wei used for the estimation.
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        virtual
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, _requestGasPriceWei);
    }

    /// @notice Calculates the total price for a request in native currency (ETH).
    /// @dev This function accounts for the base gas fee, the L1 cost,
    ///      flat fees, and other overhead costs like BLS pairing check.
    /// @dev It takes into account the L1 posting costs of the fulfillment transaction,
    ///     if we are on an L2 = (wei/gas) * gas + l1wei
    /// @param _gas The amount of gas required for the request
    /// @param _requestGasPrice The gas price in wei per gas unit
    /// @return The total price in wei for processing the request, including fees and overhead.
    function _calculateRequestPriceNative(uint256 _gas, uint256 _requestGasPrice) internal view returns (uint256) {
        // Fee in wei: gas price * gas required
        // Determine the gas price per unit based on the input or the default configuration
        uint256 weiPerUnitGas = _requestGasPrice > 0 ? _requestGasPrice : s_config.weiPerUnitGas;

        // Calculate the base fee in wei: (gas required) * (gas price per unit)
        uint256 baseFeeWei = weiPerUnitGas * (s_config.gasAfterPaymentCalculation + _gas);

        // Fetch L1 cost in wei (Layer 1 related costs)
        uint256 l1CostWei = _getL1CostWei();

        // Calculate flat fee in native currency
        uint256 flatFeeWei = 1e12 * uint256(s_config.fulfillmentFlatFeeNativePPM);

        // Calculate overhead cost for BLS pairing check
        uint256 blsPairingCheckOverheadWei = weiPerUnitGas * s_config.blsPairingCheckOverhead;

        // Calculate the total cost with flat fee and overhead, applying the native premium percentage
        // The premium is applied on baseCost = l1CostWei + baseFeeWei + blsPairingCheckOverheadWei, and then a flat fee is added:
        uint256 totalCostWithFlatFeeWei = (
            ((l1CostWei + baseFeeWei + blsPairingCheckOverheadWei) * (100 + s_config.nativePremiumPercentage)) / 100
        ) + flatFeeWei;

        return totalCostWithFlatFeeWei;
    }

    /// @notice Calculates the payment amount in native tokens, considering L1 gas fees if applicable
    /// @param startGas The initial gas amount at the start of the operation
    /// @param weiPerUnitGas The gas price in wei
    /// @return The total payment amount in native tokens (as uint96)
    function _calculatePaymentAmountNative(uint256 startGas, uint256 weiPerUnitGas) internal returns (uint96) {
        // Retrieve L1 cost (non-zero only on L2s that need to reimburse L1 gas usage)
        uint256 l1CostWei = _getL1CostWei(msg.data);

        // Calculate base gas fee: (used gas) * gas price
        uint256 gasUsed = s_config.gasAfterPaymentCalculation + startGas - gasleft();
        uint256 baseFeeWei = gasUsed * weiPerUnitGas;

        // Flat fee charged in native token (in wei)
        uint256 flatFeeWei = 1e12 * uint256(s_config.fulfillmentFlatFeeNativePPM);

        // Emit L1 fee info if applicable
        if (l1CostWei > 0) {
            emit L1GasFee(l1CostWei);
        }

        // Apply premium percentage and add flat fee
        uint256 totalFeeWei = ((l1CostWei + baseFeeWei) * (100 + s_config.nativePremiumPercentage)) / 100 + flatFeeWei;

        return uint96(totalFeeWei);
    }

    /// @notice Charges a payment against a subscription and updates contract balances
    /// @dev If `subId` is 0, payment is treated as a direct charge (no subscription tracking)
    /// @param payment The amount to charge in native tokens
    /// @param subId The subscription ID to charge; 0 means no subscription
    function _chargePayment(uint96 payment, uint256 subId) internal {
        Subscription storage subcription = s_subscriptions[subId];

        if (subId > 0) {
            uint96 prevBal = subcription.nativeBalance;

            _requireSufficientBalance(prevBal >= payment);

            subcription.nativeBalance = prevBal - payment;

            s_withdrawableSubscriptionFeeNative += payment;
        } else {
            s_withdrawableDirectFundingFeeNative += payment;
        }
    }

    /// @notice Handles payment logic and charges gas fees for a given request
    /// @dev Intended to be overridden by derived contracts to implement custom payment handling
    /// @param requestId The unique identifier of the request being processed
    /// @param startGas The amount of gas available at the start of the function execution
    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal virtual {}

    /// @notice Returns the L1 fee for fulfilling a request.
    /// @dev Always returns `0` on L1 chains.
    /// @dev Should be overridden for L2 chains.
    /// @dev E.g., Arbitrum/Optimism to cover cost for L2s posting data to Ethereum (L1).
    /// @return The L1 fee in wei.
    function _getL1CostWei() internal view virtual returns (uint256) {
        return 0;
    }

    /// @notice Returns the L1 fee for the calldata payload.
    /// @dev Always returns `0` on L1 chains. Should be overridden for L2 chains.
    /// @return The L1 fee in wei.
    function _getL1CostWei(bytes calldata /*data*/ ) internal view virtual returns (uint256) {
        return 0;
    }

    /// @dev Calculates extra amount of gas required for running an assembly call() post-EIP150.
    function _getEIP150Overhead(uint32 gas) internal pure returns (uint32) {
        return gas / 63 + 1;
    }
}

// src/decryption-requests/DecryptionReceiverBase.sol

/// @title DecryptionReceiverBase contract
/// @author Randamu
/// @notice Abstract contract for registering Ciphertexts and
/// handling the reception of decryption data from the DecryptionSender contract
abstract contract DecryptionReceiverBase is IDecryptionReceiver {
    /// @notice The DecryptionSender contract authorized to send decryption data
    IDecryptionSender public decryptionSender;

    /// @notice Modifier to restrict access to only the DecryptionSender contract
    modifier onlyDecrypter() {
        require(msg.sender == address(decryptionSender), "Only DecryptionSender can call");
        _;
    }

    /// @dev Forwards a ciphertext registration request to the DecryptionSender contract
    ///      which sets up a conditional encryption request.
    /// @param schemeID Identifier of the encryption scheme used
    /// @param callbackGasLimit Maximum gas allowed for the decryption callback
    /// @param ciphertext The encrypted data to be decrypted
    /// @param conditions Optional conditions for decryption (e.g., access control)
    /// @return requestID A unique identifier for the submitted decryption request
    function _registerCiphertext(
        string memory schemeID,
        uint32 callbackGasLimit,
        bytes memory ciphertext,
        bytes memory conditions
    ) internal returns (uint256 requestID) {
        return decryptionSender.registerCiphertext(schemeID, callbackGasLimit, ciphertext, conditions);
    }

    /// @dev Called by the DecryptionSender to deliver the decryption key and its signature
    /// @param requestID The identifier of the original decryption request
    /// @param decryptionKey The derived decryption key
    /// @param signature Signature used in the key derivation process
    function receiveDecryptionData(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external
        onlyDecrypter
    {
        onDecryptionDataReceived(requestID, decryptionKey, signature);
    }

    /// @notice Callback function triggered when a decryption key is received
    /// @dev Must be implemented in derived contracts to define how to handle the received decryption data
    /// @param requestID The unique identifier of the decryption request
    /// @param decryptionKey The decryption key associated with the ciphertext
    /// @param signature The signature used to derive the decryption key
    function onDecryptionDataReceived(uint256 requestID, bytes memory decryptionKey, bytes memory signature)
        internal
        virtual;
}

// lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlEnumerableUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.1.0) (access/extensions/AccessControlEnumerable.sol)

/**
 * @dev Extension of {AccessControl} that allows enumerating the members of each role.
 */
abstract contract AccessControlEnumerableUpgradeable is Initializable, IAccessControlEnumerable, AccessControlUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:storage-location erc7201:openzeppelin.storage.AccessControlEnumerable
    struct AccessControlEnumerableStorage {
        mapping(bytes32 role => EnumerableSet.AddressSet) _roleMembers;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControlEnumerable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlEnumerableStorageLocation = 0xc1f6fe24621ce81ec5827caf0253cadb74709b061630e6b55e82371705932000;

    function _getAccessControlEnumerableStorage() private pure returns (AccessControlEnumerableStorage storage $) {
        assembly {
            $.slot := AccessControlEnumerableStorageLocation
        }
    }

    function __AccessControlEnumerable_init() internal onlyInitializing {
    }

    function __AccessControlEnumerable_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlEnumerable).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) public view virtual returns (address) {
        AccessControlEnumerableStorage storage $ = _getAccessControlEnumerableStorage();
        return $._roleMembers[role].at(index);
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) public view virtual returns (uint256) {
        AccessControlEnumerableStorage storage $ = _getAccessControlEnumerableStorage();
        return $._roleMembers[role].length();
    }

    /**
     * @dev Return all accounts that have `role`
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function getRoleMembers(bytes32 role) public view virtual returns (address[] memory) {
        AccessControlEnumerableStorage storage $ = _getAccessControlEnumerableStorage();
        return $._roleMembers[role].values();
    }

    /**
     * @dev Overload {AccessControl-_grantRole} to track enumerable memberships
     */
    function _grantRole(bytes32 role, address account) internal virtual override returns (bool) {
        AccessControlEnumerableStorage storage $ = _getAccessControlEnumerableStorage();
        bool granted = super._grantRole(role, account);
        if (granted) {
            $._roleMembers[role].add(account);
        }
        return granted;
    }

    /**
     * @dev Overload {AccessControl-_revokeRole} to track enumerable memberships
     */
    function _revokeRole(bytes32 role, address account) internal virtual override returns (bool) {
        AccessControlEnumerableStorage storage $ = _getAccessControlEnumerableStorage();
        bool revoked = super._revokeRole(role, account);
        if (revoked) {
            $._roleMembers[role].remove(account);
        }
        return revoked;
    }
}

// lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.2.0) (proxy/utils/UUPSUpgradeable.sol)

/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 */
abstract contract UUPSUpgradeable is Initializable, IERC1822Proxiable {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address private immutable __self = address(this);

    /**
     * @dev The version of the upgrade interface of the contract. If this getter is missing, both `upgradeTo(address)`
     * and `upgradeToAndCall(address,bytes)` are present, and `upgradeTo` must be used if no function should be called,
     * while `upgradeToAndCall` will invoke the `receive` function if the second argument is the empty byte string.
     * If the getter returns `"5.0.0"`, only `upgradeToAndCall(address,bytes)` is present, and the second argument must
     * be the empty byte string if no function should be called, making it impossible to invoke the `receive` function
     * during an upgrade.
     */
    string public constant UPGRADE_INTERFACE_VERSION = "5.0.0";

    /**
     * @dev The call is from an unauthorized context.
     */
    error UUPSUnauthorizedCallContext();

    /**
     * @dev The storage `slot` is unsupported as a UUID.
     */
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC-1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC-1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        _checkProxy();
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        _checkNotDelegated();
        _;
    }

    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev Implementation of the ERC-1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual notDelegated returns (bytes32) {
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    /**
     * @dev Reverts if the execution is not performed via delegatecall or the execution
     * context is not of a proxy with an ERC-1967 compliant implementation pointing to self.
     * See {_onlyProxy}.
     */
    function _checkProxy() internal view virtual {
        if (
            address(this) == __self || // Must be called through delegatecall
            ERC1967Utils.getImplementation() != __self // Must be called through an active proxy
        ) {
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Reverts if the execution is performed via delegatecall.
     * See {notDelegated}.
     */
    function _checkNotDelegated() internal view virtual {
        if (address(this) != __self) {
            // Must not be called through delegatecall
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /**
     * @dev Performs an implementation upgrade with a security check for UUPS proxies, and additional setup call.
     *
     * As a security check, {proxiableUUID} is invoked in the new implementation, and the return value
     * is expected to be the implementation slot in ERC-1967.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
            ERC1967Utils.upgradeToAndCall(newImplementation, data);
        } catch {
            // The implementation is not UUPS
            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }
    }
}

// src/blocklock/BlocklockSender.sol

/// @title BlocklockSender Contract
/// @author Randamu
/// @notice This contract is responsible for managing the blocklock sending functionality,
///         including handling requests, decryption keys, decryption, fees, and access control.
/// @dev The contract integrates multiple functionalities including decryption receiver capabilities,
///      fee collection, and role-based access control. It is also upgradeable and follows the UUPS pattern.
///      The contract implements the `IBlocklockSender` interface and uses `DecryptionReceiverBase` for handling decryption logic.
///      Additionally, it collects fees via `BlocklockFeeCollector` and uses OpenZeppelin's upgradeable and access control mechanisms.
contract BlocklockSender is
    IBlocklockSender,
    DecryptionReceiverBase,
    BlocklockFeeCollector,
    Initializable,
    UUPSUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using BytesLib for bytes32;

    /// @notice This contract manages blocklock requests, decryption keys, and administrative roles.
    /// @dev The contract includes constants related to blocklock schemes, decryption key processing, and events for blocklock requests and callbacks.
    ///      It also defines an `ADMIN_ROLE` for managing access control and updates to decryption sender.

    /// @notice The role identifier for the admin role used for access control
    /// @dev This constant is derived from the keccak256 hash of the string "ADMIN_ROLE" and is used in access control checks
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice The Scheme ID used for the BLS-based blocklock scheme
    /// @dev This constant is used for identifying the BLS blocklock scheme, specifically for BN254 elliptic curve operations
    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";

    /// @notice The domain separation constant used for H1 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H1_G1;

    /// @notice The domain separation constant used for H2 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H2;

    /// @notice The domain separation constant used for H3 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H3;

    /// @notice The domain separation constant used for H4 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H4;

    /// @notice Mapping from a decryption request ID to its corresponding blocklock request containing the decryption key
    /// @dev The mapping is used to store blocklock requests with their decryption keys by their unique request IDs
    mapping(uint256 => TypesLib.BlocklockRequest) public blocklockRequestsWithDecryptionKey;

    /// @notice Event emitted when a blocklock request is made
    /// @param requestID The unique identifier of the blocklock request
    /// @param blockHeight The block height for which the blocklock is requested
    /// @param ciphertext The ciphertext associated with the blocklock request
    /// @param requester The address of the requester
    /// @param requestedAt The timestamp when the request was made
    /// @dev This event is emitted after a blocklock request has been successfully processed
    event BlocklockRequested(
        uint256 indexed requestID,
        uint256 blockHeight,
        TypesLib.Ciphertext ciphertext,
        address indexed requester,
        uint256 requestedAt
    );

    /// @notice Event emitted when a blocklock callback is successful
    /// @param requestID The unique identifier of the blocklock request
    /// @param blockHeight The block height for which the blocklock is requested
    /// @param ciphertext The ciphertext associated with the blocklock request
    /// @param decryptionKey The decryption key used for the blocklock
    /// @dev This event is emitted when the blocklock callback is successfully processed and the decryption key is provided
    event BlocklockCallbackSuccess(
        uint256 indexed requestID, uint256 blockHeight, TypesLib.Ciphertext ciphertext, bytes decryptionKey
    );

    /// @notice Error thrown when a blocklock callback fails
    /// @param requestID The request ID of the failed blocklock callback
    /// @dev This error is used to indicate that the blocklock callback process has failed, providing the request ID for troubleshooting
    event BlocklockCallbackFailed(uint256 requestID);

    /// @notice Event emitted when the decryption sender address is updated
    /// @param decryptionSender The new decryption sender address
    /// @dev This event is triggered when the address of the decryption sender is updated, allowing for tracking of the changes
    event DecryptionSenderUpdated(address indexed decryptionSender);

    /// @notice Modifier that restricts access to only accounts with the admin role
    /// @dev This modifier checks that the caller has the `ADMIN_ROLE` before allowing the function to be executed.
    modifier onlyAdmin() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner, address _decryptionSender) public initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();

        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        decryptionSender = IDecryptionSender(_decryptionSender);

        DST_H1_G1 =
            abi.encodePacked("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_", bytes32(getChainId()).toHexString(), "_");

        DST_H2 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H2_", bytes32(getChainId()).toHexString(), "_");

        DST_H3 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H3_", bytes32(getChainId()).toHexString(), "_");

        DST_H4 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H4_", bytes32(getChainId()).toHexString(), "_");
    }

    /// @dev Overridden upgrade authorization function to ensure only an authorized caller can authorize upgrades.
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    /// @notice Requests a blocklock for a specified block height with the provided ciphertext and subscription ID
    /// @param callbackGasLimit The gas limit allocated for the callback execution after the blocklock request
    /// @param subId The subscription ID associated with the request
    /// @param blockHeight The block height at which the blocklock is requested
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @return requestID The unique identifier for the blocklock request
    /// @dev This function allows users to request a blocklock for a specific block height. The blocklock is associated with a given subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is configured and not disabled before processing the request.
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata ciphertext
    ) public payable onlyConfiguredNotDisabled returns (uint256) {
        require(blockHeight > block.number, "blockHeight must be strictly greater than current");

        if (subId == 0) {
            require(msg.value > 0, "Direct funding required for request fulfillment callback");
        }

        TypesLib.BlocklockRequest memory r = TypesLib.BlocklockRequest({
            subId: subId,
            directFundingFeePaid: msg.value,
            decryptionRequestID: 0,
            blockHeight: blockHeight,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        /// @dev subId must be zero for direct funding or non zero for active subscription
        uint32 callbackGasLimitWithOverhead = _validateAndUpdateSubscription(callbackGasLimit, subId);

        bytes memory condition = abi.encode(blockHeight);

        uint256 decryptionRequestID =
            _registerCiphertext(SCHEME_ID, callbackGasLimitWithOverhead, abi.encode(ciphertext), condition);
        r.decryptionRequestID = uint64(decryptionRequestID);

        // Store the signature requestID for this blockHeight
        blocklockRequestsWithDecryptionKey[decryptionRequestID] = r;

        emit BlocklockRequested(decryptionRequestID, blockHeight, ciphertext, msg.sender, block.timestamp);
        return decryptionRequestID;
    }

    /// @notice Requests a blocklock for a specified block height with the provided ciphertext without a subscription ID.
    /// Requires payment to be made for the request without a subscription.
    /// @param callbackGasLimit The gas limit allocated for the callback execution after the blocklock request
    /// @param blockHeight The block height at which the blocklock is requested
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @dev This function allows users to request a blocklock for a specific block height. The blocklock is not associated with any subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is configured and not disabled before processing the request.
    function requestBlocklock(uint32 callbackGasLimit, uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        external
        payable
        onlyConfiguredNotDisabled
        returns (uint256)
    {
        uint256 decryptionRequestID = requestBlocklockWithSubscription(
            callbackGasLimit,
            0, // no subId
            blockHeight,
            ciphertext
        );
        return decryptionRequestID;
    }

    /// @notice Validates the subscription (if subId > 0) and the _callbackGasLimit
    /// @notice and updates the subscription for a given consumer.
    /// @dev This function checks the validity of the subscription and updates the subscription's state.
    /// @dev If the subscription ID is greater than zero, it ensures that the consumer has an active subscription.
    /// @dev If the subscription ID is zero, it processes a new subscription by calculating the necessary fees.
    /// @param _callbackGasLimit The gas limit for the callback function.
    /// @param _subId The subscription ID. If greater than zero, it indicates an existing subscription, otherwise, a new subscription is created.
    function _validateAndUpdateSubscription(uint32 _callbackGasLimit, uint256 _subId)
        internal
        returns (uint32 callbackGasLimitWithOverhead)
    {
        if (_subId > 0) {
            _requireValidSubscription(s_subscriptionConfigs[_subId].owner);
            // Its important to ensure that the consumer is in fact who they say they
            // are, otherwise they could use someone else's subscription balance.
            mapping(uint256 => ConsumerConfig) storage consumerConfigs = s_consumers[msg.sender];

            ConsumerConfig memory consumerConfig = consumerConfigs[_subId];
            require(consumerConfig.active, "No active subscription for caller");

            ++consumerConfig.nonce;
            ++consumerConfig.pendingReqCount;
            consumerConfigs[_subId] = consumerConfig;
        } else {
            uint256 price = _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);

            require(msg.value >= price, "Fee too low");
        }

        // No lower bound on the requested gas limit. A user could request 0 callback gas limit
        // but the overhead added covers bls pairing check operations and decryption as part of the callback
        // and any other added logic in consumer contract might lead to out of gas revert.
        require(_callbackGasLimit <= s_config.maxGasLimit, "Callback gasLimit too high");

        uint32 eip150Overhead = _getEIP150Overhead(_callbackGasLimit);
        // s_config.blsPairingCheckOverhead prevents out of gas errors when doing pairing checks
        // for signature and decryption key during callback
        callbackGasLimitWithOverhead = _callbackGasLimit + eip150Overhead + s_config.blsPairingCheckOverhead;
    }

    /// @notice Handles the reception of decryption data (decryption key and signature) for a specific decryption request
    /// @param decryptionRequestID The unique identifier for the decryption request, used to correlate the received data
    /// @param decryptionKey The decryption key received, used to decrypt the associated ciphertext
    /// @param signature The signature associated with the decryption key, ensuring its validity
    /// @dev This internal function is intended to be overridden in derived contracts to implement specific logic
    ///      that should be executed upon receiving the decryption data. It is called when decryption data is received
    ///      for a decryption request identified by `decryptionRequestID`.
    function onDecryptionDataReceived(uint256 decryptionRequestID, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        uint256 startGas = gasleft();

        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[decryptionRequestID];
        require(r.decryptionRequestID > 0, "No request for request id");

        r.signature = signature;

        (bool success,) = r.callback.call(
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestID, decryptionKey)
        );

        if (!success) {
            emit BlocklockCallbackFailed(decryptionRequestID);
        } else {
            emit BlocklockCallbackSuccess(decryptionRequestID, r.blockHeight, r.ciphertext, decryptionKey);
            blocklockRequestsWithDecryptionKey[decryptionRequestID].decryptionKey = decryptionKey;
            blocklockRequestsWithDecryptionKey[decryptionRequestID].signature = signature;
        }
        _handlePaymentAndCharge(decryptionRequestID, startGas);
    }

    /// @notice Estimates the total request price in native tokens based on the provided callback gas limit and requested gas price in wei
    /// @param _callbackGasLimit The gas limit allocated for the callback execution
    /// @param _requestGasPriceWei The gas price in wei for the request
    /// @return The estimated total price for the request in native tokens (wei)
    /// @dev This function calls the internal `_calculateRequestPriceNative` function, passing in the provided callback gas limit and requested gas price in wei
    ///      to estimate the total request price. It overrides the function from both `BlocklockFeeCollector` and `IBlocklockSender` contracts to provide the price estimation.
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, _requestGasPriceWei);
    }

    /// @notice Calculates the total request price in native tokens, considering the provided callback gas limit and the current gas price
    /// @param _callbackGasLimit The gas limit allocated for the callback execution
    /// @return The total price for the request in native tokens (wei)
    /// @dev This function calls the internal `_calculateRequestPriceNative` function, passing in the provided callback gas limit and the current
    ///      transaction gas price (`tx.gasprice`) to calculate the total request price. It overrides the function from both `BlocklockFeeCollector`
    ///      and `IBlocklockSender` contracts to provide the request price calculation.
    function calculateRequestPriceNative(uint32 _callbackGasLimit)
        public
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
    }

    /// @notice Handles the payment and charges for a request based on the subscription or direct funding.
    /// @dev This function calculates the payment for a given request, either based on a subscription or direct funding.
    /// @dev It updates the subscription and consumer state and
    ///     charges the appropriate amount based on the gas usage and payment parameters.
    /// @param requestId The ID of the request to handle payment for.
    /// @param startGas The amount of gas used at the start of the transaction,
    ///     used for calculating payment based on gas consumption.
    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal override {
        TypesLib.BlocklockRequest memory request = getRequest(requestId);

        if (request.subId > 0) {
            ++s_subscriptions[request.subId].reqCount;
            --s_consumers[request.callback][request.subId].pendingReqCount;

            uint96 payment = _calculatePaymentAmountNative(startGas, tx.gasprice);
            _chargePayment(payment, request.subId);
        } else {
            _chargePayment(uint96(request.directFundingFeePaid), request.subId);
        }
    }

    /// @notice Decrypts a ciphertext into plaintext using a decryption key
    /// @param ciphertext The ciphertext to decrypt, containing the necessary data for decryption
    /// @param decryptionKey The decryption key used to decrypt the ciphertext
    /// @return The decrypted message (plaintext) as a `bytes` array
    /// @dev This function performs the decryption process using a series of cryptographic operations:
    ///     - It first XORs the decryption key with part of the ciphertext to generate a candidate value.
    ///     - Then it decrypts the message using another XOR operation with a mask derived from the candidate value.
    ///     - The function verifies the validity of the decryption key and ciphertext by checking the consistency of a derived ephemeral keypair.
    /// @dev Throws an error if:
    ///     - The decryption key length is incorrect.
    ///     - The message length is unsupported.
    ///     - The decryption key and ciphertext do not match (validation failure).
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        public
        view
        returns (bytes memory)
    {
        require(ciphertext.v.length != 256, "invalid decryption key length");
        require(ciphertext.w.length < 256, "message of unsupported length");

        // \sigma' \gets V \xor decryptionKey
        bytes memory sigma2 = ciphertext.v;
        for (uint256 i = 0; i < decryptionKey.length; i++) {
            sigma2[i] ^= decryptionKey[i];
        }

        // Decrypt the message
        // 4: M' \gets W \xor H_4(\sigma')
        bytes memory m2 = ciphertext.w;
        bytes memory mask = BLS.expandMsg(DST_H4, sigma2, uint8(ciphertext.w.length));
        for (uint256 i = 0; i < ciphertext.w.length; i++) {
            m2[i] ^= mask[i];
        }

        // Derive the ephemeral keypair with the candidate \sigma'
        // 5: r \gets H_3(\sigma, M)
        uint256 r = BLS.hashToFieldSingle(DST_H3, bytes.concat(sigma2, m2));

        // Verify that \sigma' is consistent with the message and ephemeral public key
        // 6: if U = [r]G_2 then return M' else return \bot
        BLS.PointG1 memory rG1 = BLS.scalarMulG1Base(r);
        (bool equal, bool success) = BLS.verifyEqualityG1G2(rG1, ciphertext.u);
        // Decryption fails if a bad decryption key / ciphertext was provided
        require(equal == success == true, "invalid decryption key / ciphertext registered");

        return m2;
    }

    /// @notice Sets a new decryption sender address
    /// @param newDecryptionSender The address of the new decryption sender contract
    /// @dev Only an admin can call this function. The function updates the `decryptionSender` address
    /// and emits a `DecryptionSenderUpdated` event with the new address.
    /// @dev The `DecryptionSenderUpdated` event is emitted to notify listeners of the change in decryption sender address.
    function setDecryptionSender(address newDecryptionSender) external onlyAdmin {
        decryptionSender = IDecryptionSender(newDecryptionSender);
        emit DecryptionSenderUpdated(newDecryptionSender);
    }

    /// @notice disable this contract so that new requests will be rejected. When disabled, new requests
    /// @notice will revert but existing requests can still be fulfilled.
    function disable() external override onlyAdmin {
        s_disabled = true;

        emit Disabled();
    }

    /// @notice Enables the contract, allowing new requests to be accepted.
    /// @dev Can only be called by an admin.
    function enable() external override onlyAdmin {
        s_disabled = false;
        emit Enabled();
    }

    /// @notice Sets the configuration parameters for the contract
    /// @param maxGasLimit The maximum gas limit allowed for requests
    /// @param gasAfterPaymentCalculation The gas used after the payment calculation
    /// @param fulfillmentFlatFeeNativePPM The flat fee for fulfillment in native tokens, in parts per million (PPM)
    /// 1 PPM = 0.0001%, so: 1,000,000 PPM = 100%, 10,000 PPM = 1%, 500 PPM = 0.05%
    /// @param weiPerUnitGas Wei per unit of gas for callback gas measurements
    /// @param blsPairingCheckOverhead Gas overhead for bls pairing checks for signature and decryption key verification
    /// @param nativePremiumPercentage The percentage premium applied to the native token cost
    /// @dev Only the contract admin can call this function. It validates that the `nativePremiumPercentage` is not greater than a predefined maximum value
    /// (`PREMIUM_PERCENTAGE_MAX`). After validation, it updates the contract's configuration and emits an event `ConfigSet` with the new configuration.
    /// @dev Emits a `ConfigSet` event after successfully setting the new configuration values.
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage
    ) external override onlyAdmin {
        require(PREMIUM_PERCENTAGE_MAX > nativePremiumPercentage, "Invalid Premium Percentage");

        s_config = Config({
            maxGasLimit: maxGasLimit,
            gasAfterPaymentCalculation: gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM: fulfillmentFlatFeeNativePPM,
            weiPerUnitGas: weiPerUnitGas,
            blsPairingCheckOverhead: blsPairingCheckOverhead,
            nativePremiumPercentage: nativePremiumPercentage
        });

        s_configured = true;

        emit ConfigSet(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage
        );
    }

    /// @notice Retrieves the current configuration parameters for the contract
    /// @return maxGasLimit The maximum gas limit allowed for requests
    /// @return gasAfterPaymentCalculation The gas used after the payment calculation
    /// @return fulfillmentFlatFeeNativePPM The flat fee for fulfillment in native tokens, in parts per million (PPM)
    /// @return nativePremiumPercentage The percentage premium applied to the native token cost
    /// @dev This function returns the key configuration values from the contract's settings. These values
    /// are important for calculating request costs and applying the appropriate fees.
    function getConfig()
        external
        view
        returns (
            uint32 maxGasLimit,
            uint32 gasAfterPaymentCalculation,
            uint32 fulfillmentFlatFeeNativePPM,
            uint8 nativePremiumPercentage
        )
    {
        return (
            s_config.maxGasLimit,
            s_config.gasAfterPaymentCalculation,
            s_config.fulfillmentFlatFeeNativePPM,
            s_config.nativePremiumPercentage
        );
    }

    /// @notice Owner cancel subscription, sends remaining native tokens directly to the subscription owner.
    /// @param subId subscription id
    /// @dev notably can be called even if there are pending requests, outstanding ones may fail onchain
    function ownerCancelSubscription(uint256 subId) external override onlyAdmin {
        address subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        _cancelSubscriptionHelper(subId, subOwner);
    }

    /// @notice Withdraw native tokens earned through fulfilling requests.
    /// @param recipient The address to send the funds to.
    function withdrawSubscriptionFeesNative(address payable recipient) external override nonReentrant onlyAdmin {
        uint96 amount = s_withdrawableSubscriptionFeeNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableSubscriptionFeeNative = 0;
        // For subscription fees, we also deduct amount from s_totalNativeBalance
        // s_totalNativeBalance tracks the total native sent to/from
        // this contract through fundSubscription, cancelSubscription.
        s_totalNativeBalance -= amount;
        _mustSendNative(recipient, amount);
    }

    function withdrawDirectFundingFeesNative(address payable recipient) external override nonReentrant onlyAdmin {
        uint96 amount = s_withdrawableDirectFundingFeeNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableDirectFundingFeeNative = 0;

        _mustSendNative(recipient, amount);
    }

    /// @notice Checks whether a Blocklock request is in flight
    /// @param requestID The unique identifier for the Blocklock request
    /// @return A boolean indicating if the request is currently in flight (true) or not (false)
    /// @dev This function retrieves the associated decryption request ID for the given request ID and checks
    /// if the decryption request is still in flight using the `decryptionSender`.
    /// If the `decryptionRequestID` is 0, the request is not in flight.
    function isInFlight(uint256 requestID) external view returns (bool) {
        uint256 signatureRequestID = getRequest(requestID).decryptionRequestID;

        if (signatureRequestID == 0) {
            return false;
        }

        return decryptionSender.isInFlight(signatureRequestID);
    }

    /// @notice Retrieves a Blocklock request by its unique request ID
    /// @param requestID The unique identifier for the Blocklock request
    /// @return r The BlocklockRequest structure containing details of the request
    /// @dev Throws an error if the provided request ID is invalid (decryptionRequestID is 0).
    function getRequest(uint256 requestID) public view returns (TypesLib.BlocklockRequest memory) {
        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[requestID];
        require(r.decryptionRequestID > 0, "invalid requestID");

        return r;
    }

    /// @notice Returns the version number of the upgradeable contract
    /// @return The version number of the contract as a string
    /// @dev This function is used to identify the current version of the contract for upgrade management and version tracking.
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /// @notice Returns the current blockchain chain ID.
    /// @dev Uses inline assembly to retrieve the `chainid` opcode.
    /// @return chainId The current chain ID of the network.
    function getChainId() public view returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }
}

