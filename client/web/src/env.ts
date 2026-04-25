// Known fallback logos. We import a small set of SVG React components so
// builds can choose between them based on env variables without dynamic
// runtime imports (which would complicate the build).
import CylonixLogo from "src/assets/icons/cylonix.svg?react"
import TailscaleLogo from "src/assets/icons/tailscale-logo.svg?react"

// Read values from Vite env variables with sensible defaults. Use the
// VITE_ prefix so the values are exposed to client code.
const V = import.meta.env as Record<string, any>

export const Env = {
    appName: V.VITE_APP_NAME ?? V.VITE_APP_TITLE ?? "Cylonix",
    companyName: V.VITE_COMPANY_NAME ?? "EZBLOCK, Inc",
    supportEmail: V.VITE_SUPPORT_EMAIL ?? "contact@cylonix.io",
    website: V.VITE_WEBSITE ?? "https://cylonix.io",
    privacyPolicyURL: V.VITE_PRIVACY_URL ?? "https://manage.cylonix.io/privacy-policy",
    termsOfServiceURL: V.VITE_TERMS_URL ?? "https://manage.cylonix.io/terms-of-service",
    controlURL: V.VITE_CONTROL_URL ?? "https://manage.cylonix.io",
    daemonName: V.VITE_DAEMON_NAME ?? "cylonixd",
}

// Allow selecting between a small set of logos via VITE_LOGO (values:
// "cylonix" or "tailscale"). Defaults to "cylonix".
const logoKey = (V.VITE_LOGO ?? "cylonix").toLowerCase()
export const Logo = logoKey === "tailscale" ? TailscaleLogo : CylonixLogo