/**
 * The User-Agent on every server-side call to CoinPay. All fleet apps reach
 * CoinPay from one IP, so this is how its logs and throttle tell them apart.
 */
const APP_VERSION = process.env["npm_package_version"];

export const COINPAY_UA = `threatcrush.com${APP_VERSION ? `/${APP_VERSION}` : ""} (+https://threatcrush.com)`;
