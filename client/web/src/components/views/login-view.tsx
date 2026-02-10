// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React, { useCallback, useEffect, useState } from "react"
import { apiFetch, apiFetchRaw, useAPI } from "src/api"
import { NodeData } from "src/types"
import Button from "src/ui/button"
import { Env, Logo } from "src/env"
import useToaster from "src/hooks/toaster"
import LoadingDots from "src/ui/loading-dots"

// __BEGIN_CYLONIX_ADD__
type CylonixdLogResponse = {
  status: "ok" | "missing" | "error"
  log?: string
  updated?: string
  size?: number
  truncated?: boolean
  error?: string
}
// __END_CYLONIX_ADD__

/**
 * LoginView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginView({ data }: { data: NodeData }) {
  const api = useAPI()

  // __BEGIN_CYLONIX_ADD__
  const toaster = useToaster()
  const isSynology = data.IsSynology === true
  const isQNAP = data.IsQNAP === true
  const hasLog = isSynology || isQNAP
  const [logData, setLogData] = useState<CylonixdLogResponse | null>(null)
  const [logError, setLogError] = useState<string | null>(null)
  const [logLoading, setLogLoading] = useState(false)
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginWaitingForStateChange, setLoginWaitingForStateChange] = useState(false)
  const [downloadLoading, setDownloadLoading] = useState(false)
  const [logOpen, setLogOpen] = useState(false)

  const loadLog = useCallback(() => {
    if (!hasLog) return
    setLogLoading(true)
    setLogError(null)
    apiFetch<CylonixdLogResponse>("/cylonixd-log", "GET")
      .then((resp) => {
        setLogData(resp)
        if (resp.error) {
          setLogError(resp.error)
        }
      })
      .catch((err) => {
        setLogError(err?.message ?? String(err))
      })
      .finally(() => setLogLoading(false))
  }, [hasLog])

  useEffect(() => {
    if (hasLog && logOpen) {
      loadLog()
    }
  }, [hasLog, loadLog, logOpen])

  const downloadLog = useCallback(async () => {
    if (!hasLog || downloadLoading) return
    setDownloadLoading(true)
    setLogError(null)
    try {
      const resp = await apiFetchRaw("/cylonixd-log/download", "GET")
      const blob = await resp.blob()
      const disposition = resp.headers.get("Content-Disposition")
      const filenameMatch = disposition?.match(/filename="?([^";]+)"?/)
      const filename = filenameMatch?.[1] ?? "cylonixd.stdout.log"

      const url = window.URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.download = filename
      document.body.append(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      toaster.show({
        message: `Downloaded ${Env.daemonName} log`,
        variant: "success",
      })
    } catch (err: any) {
      setLogError(err?.message ?? String(err))
      toaster.show({
        variant: "danger",
        message: err?.message ?? "Failed to download log",
      })
    } finally {
      setDownloadLoading(false)
    }
  }, [downloadLoading, hasLog, toaster])
  // __END_CYLONIX_ADD__

  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <Logo className="my-2 mb-8" width={128} height={128} />
      {loginWaitingForStateChange ? (
        <div className="my-6">
          <p className="text-gray-700">
            Waiting for sign-in to complete.  <LoadingDots />

          </p>

          <Button
            onClick={() => {
              setLoginWaitingForStateChange(false)
              setLoginLoading(false)
            }}
            className="w-full my-4"
            intent="primary"
          >
            Cancel
          </Button>
        </div>
      ) : data.Status === "Stopped" ? (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Connect</h3>
            <p className="text-gray-700">
              Your device is disconnected from {Env.appName}.
            </p>
          </div>
          <Button
            onClick={() => {
              setLoginLoading(true)
              api({ action: "up", data: {} }).finally(() => {
                setLoginLoading(false)
              })
            }}
            loading={loginLoading}
            className="w-full mb-4"
            intent="primary"
          >
            Connect to {Env.appName}
          </Button>
        </>
      ) : data.IPv4 ? (
        <>
          <div className="mb-6">
            <p className="text-gray-700">
              Your device’s key has expired. Reauthenticate this device by
              signing in again, or{" "}
              <a
                href="https://tailscale.com/kb/1028/key-expiry"
                className="link"
                target="_blank"
                rel="noreferrer"
              >
                learn more
              </a>
              .
            </p>
          </div>
          <Button
            onClick={() => {
              setLoginLoading(true)
              api({
                action: "up", data: {
                  Reauthenticate: true,
                  ControlURL: `${Env.controlURL}`
                }
              }).then(() => {
                setLoginWaitingForStateChange(true)
              }).finally(() => {
                setLoginLoading(false)
              })
            }}
            loading={loginLoading}
            className="w-full mb-4"
            intent="primary"
          >
            Reauthenticate
          </Button>
        </>
      ) : (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Sign in</h3>
            <p className="text-gray-700">
              Get started by logging in to your {Env.appName} network.
              Or,&nbsp;learn&nbsp;more at{" "}
              <a
                href={Env.website}
                className="link"
                target="_blank"
                rel="noreferrer"
              >
                {Env.website}
              </a>
              .
            </p>
          </div>
          <Button
            onClick={() => {
              setLoginLoading(true)
              api({
                action: "up",
                data: {
                  Reauthenticate: true,
                  ControlURL: `${Env.controlURL}`
                },
              }).then(() => {
                setLoginWaitingForStateChange(true)
              }).finally(() => {
                setLoginLoading(false)
              })
            }}
            loading={loginLoading}
            className="w-full mb-4"
            intent="primary"
          >
            Sign In
          </Button>
        </>
      )}
      {hasLog && (
        <div className="mt-6 border-t pt-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
            <h4 className="text-lg font-semibold">{Env.daemonName} log</h4>
            <div className="flex items-center gap-2">
              <Button
                sizeVariant="small"
                variant="minimal"
                intent="base"
                onClick={() => setLogOpen((prev) => !prev)}
              >
                {logOpen ? "Hide" : "Show"}
              </Button>
              <Button
                sizeVariant="small"
                variant="minimal"
                intent="base"
                onClick={loadLog}
                loading={logLoading}
                disabled={!logOpen}
              >
                Refresh
              </Button>
              <Button
                sizeVariant="small"
                variant="minimal"
                intent="base"
                onClick={downloadLog}
                loading={downloadLoading}
                disabled={!logOpen}
              >
                Download
              </Button>
            </div>
          </div>
          {logOpen && (
            <>
              <p className="text-sm text-gray-600 mb-2">
                Service log status: {logData?.status ?? (logLoading ? "loading" : "unknown")}
              </p>
              {logError && (
                <p className="text-sm text-red-600 mb-2">{logError}</p>
              )}
              <div className="bg-gray-50 border border-gray-200 rounded-md p-3 text-xs font-mono whitespace-pre-wrap max-h-64 overflow-auto">
                {logData?.log
                  ? logData.log
                  : logLoading
                    ? "Loading log..."
                    : "No log data available."}
              </div>
              {logData?.updated && (
                <p className="text-xs text-gray-500 mt-2">
                  Updated {new Date(logData.updated).toLocaleString()} • {logData.size ?? 0} bytes
                  {logData.truncated ? " (truncated)" : ""}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
