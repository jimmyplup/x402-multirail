#!/usr/bin/env python3
"""ops/erc8004-register.py — Synap's ERC-8004 identity on Celo (T-954).

The Celo "Agents on Open Rails" hackathon accepts an entry "only with an
ERC-8004 identity" (loops.house FAQ), and Prezenti asks for one too. The
identity is an NFT minted by the Identity Registry's register(agentURI); the
agentURI is our registration file at
https://pool.linkrra.com/.well-known/agent-registration.json (a2a/erc8004.js).

Registering is a transaction: it costs gas. So this script is split on the
money line:

  plan   (default) FREE. Reads only: confirms the registry contract exists on
         each chain, estimates register(agentURI) gas FROM the would-be owner,
         reads the live base fee + tip, and prints the exact cost in CELO and
         the owner's current CELO / USDC / USA₮ balance. Writes nothing.

  send   Signs and broadcasts register(agentURI). Testnet (celo-sepolia) by
         default. Mainnet is REFUSED unless --mainnet-approved-by names the
         approval — spending gas is Jimmie's decision (AGENTS.md: money.spend has
         no holder), so an agent never passes that flag on its own.

  testnet-key   Create a testnet-only signing key in the macOS Keychain
         (service linkrra-erc8004-testnet) and print its public address. It is
         never used on mainnet and never holds anything of value.

The agentId is read from the Registered event in the mined receipt, never from
a simulation (docs.celo.org/build/agents/8004.md: the simulated id is wrong
whenever someone else registers first).

Usage:
  python3 ops/erc8004-register.py plan [--owner 0x...] [--uri URL] [--json]
  python3 ops/erc8004-register.py testnet-key
  python3 ops/erc8004-register.py send --network celo-sepolia
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from decimal import Decimal

NETWORKS = {
    "celo": {
        "chainId": 42220,
        "rpc": "https://forno.celo.org",
        "registry": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
        "explorer": "https://celoscan.io/tx/",
        "tokens": {"USDC": "0xcebA9300f2b948710d2653dD7B07f33A8B32118C",
                   "USAT": "0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771"},
        "testnet": False,
    },
    "celo-sepolia": {
        "chainId": 11142220,
        "rpc": "https://forno.celo-sepolia.celo-testnet.org",
        "registry": "0x8004A818BFB912233c491871b3d84c89A494BD9e",
        "explorer": "https://celo-sepolia.blockscout.com/tx/",
        "tokens": {"USDC": "0x01C5C0122039549AD1493B8220cABEdD739BC44E"},
        "testnet": True,
    },
}

# The x402 receiving wallet (memory x402-agent-payments). Registering FROM it
# makes agentWallet == the payTo every x402 rail already publishes. Its key
# lives only in the Mac Keychain (linkrra-x402-wallet / x402-receiving).
DEFAULT_OWNER = "0xAA0a350f6080940c138A8A50C0Fa8c8387782eb4"
DEFAULT_URI = "https://pool.linkrra.com/.well-known/agent-registration.json"
TESTNET_KEYCHAIN = ("linkrra-erc8004-testnet", "erc8004-testnet")

# keccak256("register(string)")[:4] and keccak256("Registered(uint256,string,address)")
# — computed with eth_utils below rather than pasted, so a typo cannot hide here.


def keccak_hex(text):
    from eth_utils import keccak
    return "0x" + keccak(text=text).hex().removeprefix("0x")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # forno.celo.org answers 403 to urllib's default User-Agent (seen 2026-10-17).
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "linkrra-ops/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def encode_register(uri):
    data = uri.encode()
    selector = keccak_hex("register(string)")[:10]
    length = len(data).to_bytes(32, "big").hex()
    padded = data.hex() + "00" * ((32 - len(data) % 32) % 32)
    return selector + (32).to_bytes(32, "big").hex() + length + padded


def balance_of(net, token, owner):
    data = "0x70a08231" + owner[2:].lower().rjust(64, "0")
    return int(rpc(net["rpc"], "eth_call", [{"to": token, "data": data}, "latest"]), 16)


def plan(owner, uri):
    report = {"owner": owner, "agentURI": uri, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "networks": {}}
    calldata = encode_register(uri)
    for name, net in NETWORKS.items():
        row = {"chainId": net["chainId"], "registry": net["registry"]}
        try:
            code = rpc(net["rpc"], "eth_getCode", [net["registry"], "latest"])
            row["registryHasCode"] = len(code) > 2
            gas = int(rpc(net["rpc"], "eth_estimateGas", [{"from": owner, "to": net["registry"], "data": calldata}]), 16)
            block = rpc(net["rpc"], "eth_getBlockByNumber", ["latest", False])
            base_fee = int(block.get("baseFeePerGas", "0x0"), 16)
            try:
                tip = int(rpc(net["rpc"], "eth_maxPriorityFeePerGas", []), 16)
            except Exception:
                tip = 0
            gas_limit = int(gas * 1.2) + 1  # 20% headroom, as a wallet would
            expected_wei = gas * (base_fee + tip)
            max_wei = gas_limit * (2 * base_fee + tip)
            native = int(rpc(net["rpc"], "eth_getBalance", [owner, "latest"]), 16)
            row.update({
                "estimatedGas": gas,
                "gasLimitWithHeadroom": gas_limit,
                "baseFeeGwei": str(Decimal(base_fee) / Decimal(10**9)),
                "tipGwei": str(Decimal(tip) / Decimal(10**9)),
                "expectedCostCELO": str(Decimal(expected_wei) / Decimal(10**18)),
                "maxCostCELO": str(Decimal(max_wei) / Decimal(10**18)),
                "ownerBalanceCELO": str(Decimal(native) / Decimal(10**18)),
                "ownerCanPayInCELO": native >= max_wei,
                "ownerTokenBalances": {
                    sym: str(Decimal(balance_of(net, addr, owner)) / Decimal(10**6)) for sym, addr in net["tokens"].items()
                },
            })
        except Exception as err:  # a failed read is a failed read, never "costs 0"
            row["error"] = str(err)
        report["networks"][name] = row
    return report


def keychain_get(service, account):
    r = subprocess.run(["security", "find-generic-password", "-s", service, "-a", account, "-w"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def testnet_key():
    from eth_account import Account
    existing = keychain_get(*TESTNET_KEYCHAIN)
    if existing:
        acct = Account.from_key(json.loads(existing)["privateKey"])
        print(f"exists: {acct.address} (Keychain {TESTNET_KEYCHAIN[0]}/{TESTNET_KEYCHAIN[1]}) — testnet only")
        return
    acct = Account.create()
    secret = json.dumps({"privateKey": acct.key.hex(), "address": acct.address,
                         "purpose": "ERC-8004 + x402 rehearsal on Celo Sepolia / Arc testnet ONLY — never fund on mainnet"})
    r = subprocess.run(["security", "add-generic-password", "-s", TESTNET_KEYCHAIN[0], "-a", TESTNET_KEYCHAIN[1],
                        "-w", secret, "-D", "linkrra testnet rehearsal key",
                        "-j", "Testnet only (Celo Sepolia, Arc testnet). Holds faucet tokens, nothing of value."],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"keychain write failed: {r.stderr.strip()}")
    if not keychain_get(*TESTNET_KEYCHAIN):
        raise SystemExit("keychain read-back failed")
    print(f"created: {acct.address} (Keychain {TESTNET_KEYCHAIN[0]}/{TESTNET_KEYCHAIN[1]}) — testnet only")


def send(network, uri, approved_by):
    from eth_account import Account
    net = NETWORKS[network]
    if not net["testnet"] and not approved_by:
        raise SystemExit(
            f"REFUSED: {network} is mainnet — register() spends real gas. Run `plan`, give Jimmie the exact "
            "cost + wallet + chain, and re-run with --mainnet-approved-by '<who, when, where>' only after he says yes."
        )
    if not net["testnet"]:
        raise SystemExit("mainnet send needs the receiving-wallet key; wire it deliberately when approved (not in T-954).")
    secret = keychain_get(*TESTNET_KEYCHAIN)
    if not secret:
        raise SystemExit("no testnet key — run `testnet-key` first, then fund its address from the Celo Sepolia faucet")
    acct = Account.from_key(json.loads(secret)["privateKey"])
    calldata = encode_register(uri)
    gas = int(rpc(net["rpc"], "eth_estimateGas", [{"from": acct.address, "to": net["registry"], "data": calldata}]), 16)
    block = rpc(net["rpc"], "eth_getBlockByNumber", ["latest", False])
    base_fee = int(block["baseFeePerGas"], 16)
    tip = int(rpc(net["rpc"], "eth_maxPriorityFeePerGas", []), 16)
    nonce = int(rpc(net["rpc"], "eth_getTransactionCount", [acct.address, "pending"]), 16)
    tx = {"type": 2, "chainId": net["chainId"], "nonce": nonce, "to": net["registry"], "value": 0,
          "data": calldata, "gas": int(gas * 1.2) + 1, "maxPriorityFeePerGas": tip,
          "maxFeePerGas": 2 * base_fee + tip}
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction.hex() if hasattr(signed, "raw_transaction") else signed.rawTransaction.hex()
    tx_hash = rpc(net["rpc"], "eth_sendRawTransaction", ["0x" + raw.removeprefix("0x")])
    print(f"sent {tx_hash} — waiting for receipt")
    receipt = None
    for _ in range(60):
        receipt = rpc(net["rpc"], "eth_getTransactionReceipt", [tx_hash])
        if receipt:
            break
        time.sleep(2)
    if not receipt or receipt["status"] != "0x1":
        raise SystemExit(f"registration not confirmed: {receipt}")
    topic = keccak_hex("Registered(uint256,string,address)")
    ids = [int(l["topics"][1], 16) for l in receipt["logs"]
           if l["address"].lower() == net["registry"].lower() and l["topics"][0] == topic]
    if len(ids) != 1:
        raise SystemExit(f"expected one Registered event, found {len(ids)} — read the receipt by hand: {tx_hash}")
    out = {"network": network, "tx": tx_hash, "explorer": net["explorer"] + tx_hash, "agentId": ids[0],
           "owner": acct.address, "agentRegistry": f"eip155:{net['chainId']}:{net['registry']}",
           "ERC8004_REGISTRATIONS": f"eip155:{net['chainId']}:{net['registry']}:{ids[0]}"}
    print(json.dumps(out, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd")
    pp = sub.add_parser("plan")
    pp.add_argument("--owner", default=DEFAULT_OWNER)
    pp.add_argument("--uri", default=DEFAULT_URI)
    pp.add_argument("--json", action="store_true")
    sub.add_parser("testnet-key")
    ps = sub.add_parser("send")
    ps.add_argument("--network", default="celo-sepolia", choices=sorted(NETWORKS))
    ps.add_argument("--uri", default=DEFAULT_URI)
    ps.add_argument("--mainnet-approved-by", default=None)
    args = p.parse_args()
    cmd = args.cmd or "plan"
    if cmd == "plan":
        rep = plan(getattr(args, "owner", DEFAULT_OWNER), getattr(args, "uri", DEFAULT_URI))
        if getattr(args, "json", False):
            print(json.dumps(rep, indent=2))
        else:
            for name, row in rep["networks"].items():
                if "error" in row:
                    print(f"{name}: READ FAILED — {row['error']}")
                    continue
                print(f"{name}: registry code={row['registryHasCode']} gas={row['estimatedGas']} "
                      f"expected={row['expectedCostCELO']} CELO max={row['maxCostCELO']} CELO | owner {rep['owner']} "
                      f"holds {row['ownerBalanceCELO']} CELO {row['ownerTokenBalances']} -> can pay: {row['ownerCanPayInCELO']}")
        if any("error" in r for r in rep["networks"].values()):
            sys.exit(1)
    elif cmd == "testnet-key":
        testnet_key()
    elif cmd == "send":
        send(args.network, args.uri, args.mainnet_approved_by)


if __name__ == "__main__":
    main()
