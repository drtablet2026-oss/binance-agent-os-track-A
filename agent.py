"""
Binance Agent OS — Real Trading & Account Agent
================================================

A security-first, reasoning-ready trading agent.

NATURAL LANGUAGE EXAMPLES
-------------------------

Spot:
    buy BTC for $5
    sell BTCUSDT for $5
    buy ETHUSDT spot for $10

Futures:
    open long BTCUSDT futures with margin $10 at 50x
    open short BTCUSDT futures with margin $10 at 20x
    close BTCUSDT futures

Account:
    what's my balance
    show my account
    show my open positions
    show my orders

SECURITY MODEL
--------------

ALLOWED:
    - Account information (non-sensitive)
    - Balances
    - Positions
    - Orders
    - Market information
    - Spot trading
    - Futures trading
    - Asset conversion through supported trading operations
    - Futures leverage
    - Order status

PERMANENTLY BLOCKED:
    - Withdrawals
    - Internal transfers
    - UID transfers
    - User-to-user transfers
    - Sending funds to another address
    - API key/secret disclosure
    - Password/2FA/private-key/seed-phrase handling

IMPORTANT:
    The blocked operations are not merely rejected by the language
    parser. There are NO transfer/withdrawal execution methods in
    this client.

REAL TRADING
------------

Environment variables:

    BINANCE_API_KEY
    BINANCE_API_SECRET
    BINANCE_LIVE_TRADING=true

For safe testing:

    BINANCE_LIVE_TRADING=false

Never hard-code API credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests


# ============================================================
# CONFIGURATION
# ============================================================

SPOT_BASE_URL = "https://api.binance.com"
FUTURES_BASE_URL = "https://fapi.binance.com"

API_KEY = os.getenv("BINANCE_API_KEY")
API_SECRET = os.getenv("BINANCE_API_SECRET")

LIVE_TRADING = (
    os.getenv("BINANCE_LIVE_TRADING", "false").lower()
    == "true"
)

REQUEST_TIMEOUT = 15

# Local execution safety ceiling.
# Exchange-specific limits are checked separately.
MAX_FUTURES_LEVERAGE = int(
    os.getenv("BINANCE_MAX_LEVERAGE", "125")
)

MAX_SPOT_ORDER_USD = Decimal(
    os.getenv("BINANCE_MAX_SPOT_ORDER_USD", "1000")
)

MAX_FUTURES_MARGIN_USD = Decimal(
    os.getenv("BINANCE_MAX_FUTURES_MARGIN_USD", "100")
)


# ============================================================
# ERRORS
# ============================================================

class AgentError(Exception):
    """Base Agent OS error."""


class CommandError(AgentError):
    """Natural language command could not be parsed."""


class RiskError(AgentError):
    """Order rejected by security/risk layer."""


class BinanceError(AgentError):
    """Binance API error."""


class SecurityError(AgentError):
    """Security policy violation."""


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class TradeCommand:
    market: str
    symbol: str
    side: str

    quote_amount: Optional[Decimal] = None
    quantity: Optional[Decimal] = None

    margin: Optional[Decimal] = None
    leverage: Optional[int] = None

    reduce_only: bool = False


@dataclass
class OrderResult:
    success: bool
    market: str
    symbol: str
    side: str

    order_id: Optional[str] = None
    status: Optional[str] = None
    executed_quantity: Optional[str] = None
    average_price: Optional[str] = None

    error: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# ============================================================
# SECURITY POLICY
# ============================================================

class SecurityPolicy:
    """
    Central security boundary.

    Financial information may be read when it is not a secret.

    Fund-movement operations are permanently prohibited.

    This class deliberately contains no method that can execute:
        - withdrawal
        - UID transfer
        - internal transfer
        - external address transfer
    """

    BLOCKED_TERMS = (
        "withdraw",
        "withdrawal",
        "send funds",
        "send money",
        "transfer",
        "internal transfer",
        "uid transfer",
        "user transfer",
        "transfer to user",
        "send to uid",
        "send to address",
        "deposit address",
        "external wallet",
    )

    SENSITIVE_TERMS = (
        "api key",
        "api secret",
        "secret key",
        "private key",
        "seed phrase",
        "recovery phrase",
        "password",
        "2fa",
        "otp",
        "verification code",
        "security code",
    )

    @classmethod
    def is_blocked_action(cls, text: str) -> bool:
        normalized = text.lower()

        return any(
            term in normalized
            for term in cls.BLOCKED_TERMS
        )

    @classmethod
    def requests_sensitive_information(
        cls,
        text: str,
    ) -> bool:

        normalized = text.lower()

        return any(
            term in normalized
            for term in cls.SENSITIVE_TERMS
        )

    @classmethod
    def enforce_command(cls, text: str) -> None:

        if cls.is_blocked_action(text):
            raise SecurityError(
                "This action is permanently disabled in "
                "Agent OS for security. Withdrawals and "
                "fund transfers cannot be executed."
            )

        if cls.requests_sensitive_information(text):
            raise SecurityError(
                "Sensitive credentials or security secrets "
                "cannot be disclosed or handled by Agent OS."
            )


# ============================================================
# BINANCE CLIENT
# ============================================================

class BinanceClient:
    """
    Minimal signed Binance REST client.

    Intentionally supported:
        - market data
        - account information
        - Spot orders
        - Futures orders
        - Futures leverage

    Intentionally NOT implemented:
        - withdrawals
        - transfers
        - UID transfers
        - address transfers
    """

    def __init__(self) -> None:

        if not API_KEY or not API_SECRET:
            raise BinanceError(
                "BINANCE_API_KEY and BINANCE_API_SECRET "
                "are not configured."
            )

        self.api_key = API_KEY
        self.api_secret = API_SECRET

        self.session = requests.Session()

        self.session.headers.update(
            {
                "X-MBX-APIKEY": self.api_key,
                "User-Agent": "Binance-Agent-OS/1.0",
            }
        )

    # --------------------------------------------------------
    # Public request
    # --------------------------------------------------------

    def public_request(
        self,
        base_url: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        response = self.session.get(
            f"{base_url}{endpoint}",
            params=params or {},
            timeout=REQUEST_TIMEOUT,
        )

        try:
            data = response.json()
        except Exception:
            raise BinanceError(
                f"Invalid exchange response: {response.text}"
            )

        if response.status_code >= 400:
            raise BinanceError(
                data.get(
                    "msg",
                    "Unknown Binance API error.",
                )
            )

        return data

    # --------------------------------------------------------
    # Signed request
    # --------------------------------------------------------

    def signed_request(
        self,
        method: str,
        base_url: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        params = dict(params or {})

        params["timestamp"] = int(
            time.time() * 1000
        )

        params["recvWindow"] = 5000

        query = urlencode(
            params,
            doseq=True,
        )

        signature = hmac.new(
            self.api_secret.encode("utf-8"),
            query.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        query = (
            f"{query}&signature={signature}"
        )

        response = self.session.request(
            method=method,
            url=f"{base_url}{endpoint}?{query}",
            timeout=REQUEST_TIMEOUT,
        )

        try:
            data = response.json()
        except Exception:
            raise BinanceError(
                f"Invalid exchange response: {response.text}"
            )

        if response.status_code >= 400:
            code = data.get(
                "code",
                response.status_code,
            )

            message = data.get(
                "msg",
                "Unknown Binance API error.",
            )

            raise BinanceError(
                f"Binance error {code}: {message}"
            )

        return data

    # ========================================================
    # MARKET DATA
    # ========================================================

    def spot_price(
        self,
        symbol: str,
    ) -> Decimal:

        data = self.public_request(
            SPOT_BASE_URL,
            "/api/v3/ticker/price",
            {"symbol": symbol},
        )

        return Decimal(data["price"])

    def futures_price(
        self,
        symbol: str,
    ) -> Decimal:

        data = self.public_request(
            FUTURES_BASE_URL,
            "/fapi/v1/ticker/price",
            {"symbol": symbol},
        )

        return Decimal(data["price"])

    # ========================================================
    # SYMBOL INFORMATION
    # ========================================================

    def spot_symbol_info(
        self,
        symbol: str,
    ) -> Dict[str, Any]:

        data = self.public_request(
            SPOT_BASE_URL,
            "/api/v3/exchangeInfo",
            {"symbol": symbol},
        )

        symbols = data.get("symbols", [])

        if not symbols:
            raise BinanceError(
                f"Spot symbol {symbol} does not exist."
            )

        return symbols[0]

    def futures_symbol_info(
        self,
        symbol: str,
    ) -> Dict[str, Any]:

        data = self.public_request(
            FUTURES_BASE_URL,
            "/fapi/v1/exchangeInfo",
        )

        for item in data.get("symbols", []):

            if item["symbol"] == symbol:
                return item

        raise BinanceError(
            f"Futures symbol {symbol} does not exist."
        )

    # ========================================================
    # ACCOUNT INFORMATION
    # ========================================================

    def spot_account(self) -> Dict[str, Any]:

        return self.signed_request(
            "GET",
            SPOT_BASE_URL,
            "/api/v3/account",
        )

    def futures_account(self) -> Dict[str, Any]:

        return self.signed_request(
            "GET",
            FUTURES_BASE_URL,
            "/fapi/v2/account",
        )

    def spot_order(
        self,
        symbol: str,
        order_id: str,
    ) -> Dict[str, Any]:

        return self.signed_request(
            "GET",
            SPOT_BASE_URL,
            "/api/v3/order",
            {
                "symbol": symbol,
                "orderId": order_id,
            },
        )

    def futures_order(
        self,
        symbol: str,
        order_id: str,
    ) -> Dict[str, Any]:

        return self.signed_request(
            "GET",
            FUTURES_BASE_URL,
            "/fapi/v1/order",
            {
                "symbol": symbol,
                "orderId": order_id,
            },
        )

    # ========================================================
    # SPOT EXECUTION
    # ========================================================

    def place_spot_market_order(
        self,
        symbol: str,
        side: str,
        quote_amount: Optional[Decimal] = None,
        quantity: Optional[Decimal] = None,
    ) -> Dict[str, Any]:

        params: Dict[str, Any] = {
            "symbol": symbol,
            "side": side,
            "type": "MARKET",
        }

        if quote_amount is not None:
            params["quoteOrderQty"] = str(
                quote_amount
            )

        elif quantity is not None:
            params["quantity"] = str(
                quantity
            )

        else:
            raise CommandError(
                "Spot order requires an amount or quantity."
            )

        return self.signed_request(
            "POST",
            SPOT_BASE_URL,
            "/api/v3/order",
            params,
        )

    # ========================================================
    # FUTURES LEVERAGE
    # ========================================================

    def set_futures_leverage(
        self,
        symbol: str,
        leverage: int,
    ) -> Dict[str, Any]:

        return self.signed_request(
            "POST",
            FUTURES_BASE_URL,
            "/fapi/v1/leverage",
            {
                "symbol": symbol,
                "leverage": leverage,
            },
        )

    # ========================================================
    # FUTURES EXECUTION
    # ========================================================

    def place_futures_market_order(
        self,
        symbol: str,
        side: str,
        quantity: Decimal,
        reduce_only: bool = False,
    ) -> Dict[str, Any]:

        params: Dict[str, Any] = {
            "symbol": symbol,
            "side": side,
            "type": "MARKET",
            "quantity": str(quantity),
        }

        if reduce_only:
            params["reduceOnly"] = "true"

        return self.signed_request(
            "POST",
            FUTURES_BASE_URL,
            "/fapi/v1/order",
            params,
        )


# ============================================================
# NATURAL LANGUAGE COMMAND PARSER
# ============================================================

class TradingCommandParser:

    LEVERAGE_RE = re.compile(
        r"(\d+)\s*x",
        re.IGNORECASE,
    )

    MONEY_RE = re.compile(
        r"(?:\$|usd\s*)?(\d+(?:\.\d+)?)",
        re.IGNORECASE,
    )

    SUPPORTED_ASSETS = (
        "BTC",
        "ETH",
        "BNB",
        "SOL",
        "XRP",
        "DOGE",
        "ADA",
        "AVAX",
        "LINK",
        "DOT",
        "TRX",
        "LTC",
        "BCH",
        "XAU",
    )

    def parse(
        self,
        text: str,
    ) -> TradeCommand:

        original = text.strip()

        if not original:
            raise CommandError(
                "Empty command."
            )

        SecurityPolicy.enforce_command(
            original
        )

        normalized = original.lower()

        # ----------------------------------------------------
        # MARKET
        # ----------------------------------------------------

        futures = any(
            word in normalized
            for word in (
                "future",
                "futures",
                "perpetual",
                "perp",
            )
        )

        market = (
            "futures"
            if futures
            else "spot"
        )

        # ----------------------------------------------------
        # SIDE
        # ----------------------------------------------------

        if re.search(
            r"\b(buy|purchase|long)\b",
            normalized,
        ):
            side = "BUY"

        elif re.search(
            r"\b(sell|short)\b",
            normalized,
        ):
            side = "SELL"

        else:
            raise CommandError(
                "I could not determine BUY or SELL."
            )

        # ----------------------------------------------------
        # SYMBOL
        # ----------------------------------------------------

        upper = original.upper()

        pair_match = re.search(
            r"\b[A-Z0-9]{2,20}"
            r"(?:USDT|USDC|FDUSD)\b",
            upper,
        )

        if pair_match:
            symbol = pair_match.group(0)

        else:

            asset_match = None

            for asset in self.SUPPORTED_ASSETS:

                if re.search(
                    rf"\b{asset}\b",
                    upper,
                ):
                    asset_match = asset
                    break

            if not asset_match:
                raise CommandError(
                    "I could not determine the trading asset."
                )

            symbol = (
                asset_match + "USDT"
            )

        # ----------------------------------------------------
        # AMOUNT
        # ----------------------------------------------------

        amounts = self.MONEY_RE.findall(
            normalized
        )

        if not amounts:
            raise CommandError(
                "No USD amount was found."
            )

        amount = Decimal(
            amounts[0]
        )

        if amount <= 0:
            raise CommandError(
                "Amount must be greater than zero."
            )

        # ----------------------------------------------------
        # LEVERAGE
        # ----------------------------------------------------

        leverage_match = (
            self.LEVERAGE_RE.search(
                normalized
            )
        )

        leverage = (
            int(
                leverage_match.group(1)
            )
            if leverage_match
            else None
        )

        # ----------------------------------------------------
        # FUTURES MARGIN
        # ----------------------------------------------------

        margin = None

        if futures:

            margin_match = re.search(
                r"margin\s*(?:of|=)?"
                r"\s*\$?\s*"
                r"(\d+(?:\.\d+)?)",
                normalized,
            )

            if margin_match:

                margin = Decimal(
                    margin_match.group(1)
                )

            else:

                margin = amount

        return TradeCommand(
            market=market,
            symbol=symbol,
            side=side,
            quote_amount=(
                None
                if futures
                else amount
            ),
            margin=margin,
            leverage=leverage,
        )


# ============================================================
# RISK ENGINE
# ============================================================

class RiskEngine:
    def __init__(self):
        self.max_spot_usd = Decimal(
            os.getenv("BINANCE_MAX_SPOT_ORDER_USD", "1000")
        )
        self.max_futures_margin_usd = Decimal(
            os.getenv("BINANCE_MAX_FUTURES_MARGIN_USD", "100")
        )
        self.max_leverage = int(
            os.getenv("BINANCE_MAX_LEVERAGE", "125")
        )

    def validate(self, cmd):
        if cmd.amount_usd <= 0:
            raise RiskError("Trade amount must be greater than zero.")

        if cmd.market == "spot":
            if cmd.amount_usd > self.max_spot_usd:
                raise RiskError(
                    f"Spot amount exceeds the Agent OS limit "
                    f"of ${self.max_spot_usd}."
                )

        elif cmd.market == "futures":
            if cmd.amount_usd > self.max_futures_margin_usd:
                raise RiskError(
                    f"Futures margin exceeds the Agent OS limit "
                    f"of ${self.max_futures_margin_usd}."
                )

            if cmd.leverage < 1 or cmd.leverage > self.max_leverage:
                raise RiskError(
                    f"Leverage must be between 1x and "
                    f"{self.max_leverage}x."
                )

        else:
            raise RiskError("Unsupported trading market.")

        return True


# ============================================================
# ACCOUNT INFORMATION SERVICE
# ============================================================

class AccountInformationService:
    def __init__(self, client):
        self.client = client

    def balance(self):
        data = self.client.spot_account()
        result = []

        for item in data.get("balances", []):
            free = Decimal(item.get("free", "0"))
            locked = Decimal(item.get("locked", "0"))

            if free != 0 or locked != 0:
                result.append({
                    "asset": item["asset"],
                    "free": str(free),
                    "locked": str(locked)
                })

        return result

    def positions(self):
        data = self.client.futures_account()
        result = []

        for p in data.get("positions", []):
            amount = Decimal(p.get("positionAmt", "0"))

            if amount != 0:
                result.append({
                    "symbol": p["symbol"],
                    "amount": p["positionAmt"],
                    "entry": p["entryPrice"],
                    "mark": p["markPrice"],
                    "pnl": p["unRealizedProfit"],
                    "leverage": p["leverage"]
                })

        return result


# ============================================================
# TRADING COMMAND
# ============================================================

@dataclass
class TradingCommand:
    market: str
    action: str
    symbol: str
    amount_usd: Decimal
    leverage: int = 1


# ============================================================
# NATURAL LANGUAGE TRADING COMMAND PARSER
# ============================================================

class TradingCommandParser:

    @staticmethod
    def parse(text):
        t = text.lower().replace(",", " ")

        # ----------------------------------------------------
        # AMOUNT
        # Supports: $5, $10, 27 USDT, 50 USD etc.
        # ----------------------------------------------------

        amount = None

        m = re.search(
            r"\$\s*(\d+(?:\.\d+)?)",
            t
        )

        if m:
            amount = Decimal(m.group(1))

        if amount is None:
            m = re.search(
                r"\b(\d+(?:\.\d+)?)\s*(?:usd|usdt|dollar|dollars)\b",
                t
            )

            if m:
                amount = Decimal(m.group(1))

        if amount is None:
            return None

        if amount <= 0:
            return None

        # ----------------------------------------------------
        # LEVERAGE
        # ----------------------------------------------------

        leverage = 1

        m = re.search(
            r"\b(\d+)\s*x\b",
            t
        )

        if m:
            leverage = int(m.group(1))

        # ----------------------------------------------------
        # MARKET
        # ----------------------------------------------------

        futures = any(
            word in t
            for word in (
                "futures",
                "future",
                "long",
                "short",
                "leverage",
                "margin"
            )
        )

        # ----------------------------------------------------
        # ACTION
        # ----------------------------------------------------

        if "short" in t:
            action = "SHORT"
            futures = True

        elif "long" in t:
            action = "LONG"
            futures = True

        elif "sell" in t:
            action = "SELL"

        elif "buy" in t:
            action = "BUY"

        elif "convert" in t:
            action = "SELL"

        else:
            return None

        # ----------------------------------------------------
        # SYMBOL
        # ----------------------------------------------------

        upper = text.upper()

        symbols = re.findall(
            r"\b[A-Z0-9]{3,20}\b",
            upper
        )

        ignored = {
            "BUY",
            "SELL",
            "LONG",
            "SHORT",
            "FUTURES",
            "FUTURE",
            "MARGIN",
            "LEVERAGE",
            "USDT",
            "USDC",
            "USD",
            "FOR",
            "WITH",
            "AT",
            "CONVERT",
            "TO"
        }

        symbol = None

        for s in symbols:
            if s not in ignored and not s.isdigit():
                symbol = s
                break

        if not symbol:
            symbol = "BTCUSDT"

        # BTC -> BTCUSDT
        if not symbol.endswith(
            ("USDT", "USDC", "BUSD")
        ):
            symbol += "USDT"

        market = (
            "futures"
            if futures
            else "spot"
        )

        return TradingCommand(
            market=market,
            action=action,
            symbol=symbol,
            amount_usd=amount,
            leverage=leverage
        )


# ============================================================
# ACCOUNT ROUTING
# ============================================================

class AccountRouter:
    def __init__(self, account):
        self.account = account

    def route(self, text):
        t = text.lower()

        if any(x in t for x in (
            "balance",
            "balances",
            "wallet",
            "account balance",
            "mera balance"
        )):
            return (
                "balance",
                self.account.balance()
            )

        if any(x in t for x in (
            "open position",
            "open positions",
            "positions",
            "position"
        )):
            return (
                "positions",
                self.account.positions()
            )

        return None


# ============================================================
# RESPONSE FORMATTING
# ============================================================

class ResponseFormatter:

    @staticmethod
    def balance(data):
        if not data:
            return "No non-zero Spot balances found."

        lines = ["ACCOUNT BALANCE"]

        for x in data:
            lines.append(
                f'{x["asset"]}: '
                f'free={x["free"]}, '
                f'locked={x["locked"]}'
            )

        return "\n".join(lines)

    @staticmethod
    def positions(data):
        if not data:
            return "No open Futures positions."

        lines = ["OPEN FUTURES POSITIONS"]

        for p in data:
            lines.append(
                f'{p["symbol"]} | '
                f'Amount: {p["amount"]} | '
                f'Entry: {p["entry"]} | '
                f'Mark: {p["mark"]} | '
                f'PnL: {p["pnl"]} | '
                f'Leverage: {p["leverage"]}x'
            )

        return "\n".join(lines)

    @staticmethod
    def preview(cmd):
        text = [
            "PREVIEW MODE",
            f"Market: {cmd.market}",
            f"Action: {cmd.action}",
            f"Symbol: {cmd.symbol}",
            f"Amount/Margin: ${cmd.amount_usd}"
        ]

        if cmd.market == "futures":
            text.append(
                f"Leverage: {cmd.leverage}x"
            )

        text.append(
            "No real order was sent."
        )

        return "\n".join(text)

    @staticmethod
    def order(cmd, result, quantity=None):
        lines = [
            "ORDER EXECUTED",
            f"Market: {cmd.market}",
            f"Action: {cmd.action}",
            f"Symbol: {cmd.symbol}",
            f"Amount/Margin: ${cmd.amount_usd}"
        ]

        if cmd.market == "futures":
            lines.append(
                f"Leverage: {cmd.leverage}x"
            )

        if quantity is not None:
            lines.append(
                f"Quantity: {quantity}"
            )

        lines.append(
            f'Order ID: {result.get("orderId", "N/A")}'
        )

        return "\n".join(lines)


# ============================================================
# TRADING AGENT
# ============================================================

class TradingAgent:

    def __init__(self, client, risk):
        self.client = client
        self.risk = risk

        self.live = (
            os.getenv(
                "BINANCE_LIVE_TRADING",
                "false"
            ).lower() == "true"
        )

    # --------------------------------------------------------
    # EXCHANGE LEVERAGE VALIDATION
    # --------------------------------------------------------

    def validate_leverage(self, symbol, leverage):
        if leverage < 1:
            raise RiskError(
                "Leverage must be at least 1x."
            )

        if leverage > self.risk.max_leverage:
            raise RiskError(
                f"{leverage}x exceeds Agent OS maximum "
                f"of {self.risk.max_leverage}x."
            )

        info = self.client.futures_symbol_info(
            symbol
        )

        if not info:
            raise CommandError(
                f"{symbol} is not available on Binance Futures."
            )

        # If exchangeInfo provides leverage information,
        # respect it when available.
        exchange_max = None

        for key in (
            "maxLeverage",
            "leverage",
            "initialLeverage"
        ):
            value = info.get(key)

            if value:
                try:
                    exchange_max = int(value)
                    break
                except (ValueError, TypeError):
                    pass

        if exchange_max is not None:
            if leverage > exchange_max:
                raise RiskError(
                    f"{symbol} supports up to {exchange_max}x "
                    f"leverage according to exchange data."
                )

        return info

    # --------------------------------------------------------
    # QUANTITY NORMALISATION
    # --------------------------------------------------------

    @staticmethod
    def normalize_quantity(quantity, info):
        filters = {
            f["filterType"]: f
            for f in info.get("filters", [])
        }

        lot = (
            filters.get("MARKET_LOT_SIZE")
            or filters.get("LOT_SIZE")
        )

        if not lot:
            return quantity

        step = Decimal(
            lot.get("stepSize", "0")
        )

        if step <= 0:
            return quantity

        quantity = (
            quantity // step
        ) * step

        return quantity

    # --------------------------------------------------------
    # MINIMUM QUANTITY VALIDATION
    # --------------------------------------------------------

    @staticmethod
    def validate_quantity(quantity, info):
        filters = {
            f["filterType"]: f
            for f in info.get("filters", [])
        }

        lot = (
            filters.get("MARKET_LOT_SIZE")
            or filters.get("LOT_SIZE")
        )

        if lot:
            minimum = Decimal(
                lot.get("minQty", "0")
            )

            if minimum > 0 and quantity < minimum:
                raise RiskError(
                    f"Calculated quantity {quantity} is below "
                    f"exchange minimum {minimum}."
                )

    # --------------------------------------------------------
    # SPOT EXECUTION
    # --------------------------------------------------------

    def spot(self, cmd):
        if cmd.action not in (
            "BUY",
            "SELL"
        ):
            raise CommandError(
                "Spot supports BUY and SELL."
            )

        info = self.client.spot_symbol_info(
            cmd.symbol
        )

        if not info:
            raise CommandError(
                f"{cmd.symbol} is not available on Binance Spot."
            )

        self.risk.validate(cmd)

        # Preview mode
        if not self.live:
            return ResponseFormatter.preview(cmd)

        # Actual market order
        result = self.client.spot_market_order(
            symbol=cmd.symbol,
            side=cmd.action,
            quote_amount=cmd.amount_usd
        )

        return ResponseFormatter.order(
            cmd,
            result
        )

    # --------------------------------------------------------
    # FUTURES EXECUTION
    # --------------------------------------------------------

    def futures(self, cmd):
        if cmd.action not in (
            "LONG",
            "SHORT"
        ):
            raise CommandError(
                "Futures supports LONG and SHORT."
            )

        # Exchange symbol + leverage validation
        info = self.validate_leverage(
            cmd.symbol,
            cmd.leverage
        )

        # Local risk validation
        self.risk.validate(cmd)

        # Current market price
        price = Decimal(
            str(
                self.client.futures_price(
                    cmd.symbol
                )
            )
        )

        if price <= 0:
            raise BinanceError(
                "Invalid Futures market price."
            )

        # Margin × leverage = approximate notional
        notional = (
            cmd.amount_usd *
            Decimal(cmd.leverage)
        )

        quantity = (
            notional / price
        )

        # Normalize to Binance step size
        quantity = self.normalize_quantity(
            quantity,
            info
        )

        # Validate minimum quantity
        self.validate_quantity(
            quantity,
            info
        )

        if quantity <= 0:
            raise RiskError(
                "Calculated Futures quantity is invalid."
            )

        # Preview mode
        if not self.live:
            return ResponseFormatter.preview(cmd)

        # Set exchange leverage
        self.client.set_futures_leverage(
            cmd.symbol,
            cmd.leverage
        )

        # LONG = BUY
        # SHORT = SELL
        side = (
            "BUY"
            if cmd.action == "LONG"
            else "SELL"
        )

        # Actual market order
        result = self.client.futures_market_order(
            symbol=cmd.symbol,
            side=side,
            quantity=quantity
        )

        return ResponseFormatter.order(
            cmd,
            result,
            quantity
        )

    # --------------------------------------------------------
    # EXECUTION ROUTER
    # --------------------------------------------------------

    def execute(self, cmd):
        if cmd.market == "spot":
            return self.spot(cmd)

        if cmd.market == "futures":
            return self.futures(cmd)

        raise CommandError(
            f"Unsupported market: {cmd.market}"
        )


# ============================================================
# MAIN CHAT INTERFACE
# ============================================================

class BinanceAgentOS:

    def __init__(self):
        self.policy = SecurityPolicy()
        self.client = BinanceClient()
        self.risk = RiskEngine()

        self.account = AccountInformationService(
            self.client
        )

        self.account_router = AccountRouter(
            self.account
        )

        self.trader = TradingAgent(
            self.client,
            self.risk
        )

    # --------------------------------------------------------
    # SECURITY BOUNDARY
    # --------------------------------------------------------

    def security_check(self, text):
        t = text.lower()

        # Permanently forbidden
        blocked = (
            "withdraw",
            "withdrawal",
            "transfer",
            "internal transfer",
            "uid",
            "send to friend",
            "send money",
            "send usdt",
            "send crypto",
            "fund transfer"
        )

        if any(x in t for x in blocked):
            raise SecurityError(
                "BLOCKED: withdrawals and fund transfers "
                "are permanently disabled in Agent OS."
            )

        # Confidential information
        sensitive = (
            "api key",
            "api secret",
            "secret key",
            "private key",
            "seed phrase",
            "mnemonic",
            "password",
            "otp",
            "2fa"
        )

        if any(x in t for x in sensitive):
            raise SecurityError(
                "I cannot expose confidential credentials "
                "or authentication secrets."
            )

    # --------------------------------------------------------
    # ACCOUNT INFORMATION ROUTING
    # --------------------------------------------------------

    def account_request(self, text):
        result = self.account_router.route(text)

        if not result:
            return None

        kind, data = result

        if kind == "balance":
            return ResponseFormatter.balance(
                data
            )

        if kind == "positions":
            return ResponseFormatter.positions(
                data
            )

        return None

    # --------------------------------------------------------
    # MAIN CHAT
    # --------------------------------------------------------

    def chat(self, text):
        if not text or not text.strip():
            return "Please enter a command."

        try:
            # Security first
            self.security_check(text)

            # Account questions
            account = self.account_request(text)

            if account is not None:
                return account

            # Trading command
            command = TradingCommandParser.parse(
                text
            )

            if not command:
                return (
                    "I couldn't understand that command.\n\n"
                    "Examples:\n"
                    "Buy BTC for $5\n"
                    "Sell BTC for $27\n"
                    "Buy BTC for $100\n"
                    "Long BTCUSDT with $10 margin at 50x\n"
                    "Short BTCUSDT with $20 margin at 20x"
                )

            # Execute / Preview
            return self.trader.execute(
                command
            )

        except AgentError as e:
            return f"ERROR: {e}"

        except requests.RequestException as e:
            return f"NETWORK ERROR: {e}"

        except Exception as e:

          # ============================================================
# SIMPLE CHAT API
# ============================================================

_agent = None


def get_agent():
    global _agent

    if _agent is None:
        _agent = BinanceAgentOS()

    return _agent


def chat(message):
    return get_agent().chat(
        message
  )


# ============================================================
# CLI
# ============================================================

def run_cli():
    print("=" * 60)
    print("BINANCE AGENT OS")
    print("=" * 60)

    mode = (
        "LIVE TRADING"
        if get_agent().trader.live
        else "PREVIEW / DRY RUN"
    )

    print(f"MODE: {mode}")
    print()
    print("Examples:")
    print("  Buy BTC for $5")
    print("  Buy BTC for $27")
    print("  Sell BTC for $100")
    print("  Long BTCUSDT with $10 margin at 50x")
    print("  Short BTCUSDT with $20 margin at 20x")
    print("  Show my balance")
    print("  Show my open positions")
    print()
    print("Withdrawal and transfers are permanently blocked.")
    print("Type 'exit' to quit.")
    print("=" * 60)

    while True:
        try:
            message = input("\nYou: ").strip()

            if message.lower() in (
                "exit",
                "quit",
                "bye"
            ):
                print("Agent OS: Goodbye.")
                break
              if not message:
                continue

            response = chat(message)

            print("\nAgent OS:")
            print(response)

        except KeyboardInterrupt:
            print("\nAgent OS: Goodbye.")
            break


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    run_cli()
