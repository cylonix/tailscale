// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { useAPI } from "src/api"
import { NodeData } from "src/types"
import Button from "src/ui/button"
import { Env, Logo } from "src/env"

/**
 * LoginView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginView({ data }: { data: NodeData }) {
  const api = useAPI()

  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <Logo className="my-2 mb-8" width={128} height={128} />
      {data.Status === "Stopped" ? (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Connect</h3>
            <p className="text-gray-700">
              Your device is disconnected from {Env.appName}.
            </p>
          </div>
          <Button
            onClick={() => api({ action: "up", data: {} })}
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
            onClick={() =>
              api({
                action: "up", data: {
                  Reauthenticate: true,
                  ControlURL: `${Env.controlURL}`
                }
              })
            }
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
            onClick={() =>
              api({
                action: "up",
                data: {
                  Reauthenticate: true,
                  ControlURL: `${Env.controlURL}`
                },
              })
            }
            className="w-full mb-4"
            intent="primary"
          >
            Sign In
          </Button>
        </>
      )}
    </div>
  )
}
