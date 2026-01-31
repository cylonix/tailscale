// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { Env, Logo } from "src/env"
/**
 * DisconnectedView is rendered after node logout.
 */
export default function DisconnectedView() {
  return (
    <>
      <Logo className="mx-auto" width={128} height={128} />
      <p className="mt-12 text-center text-text-muted">
        You Signed out of this device. To reconnect it you will have to
        re-authenticate the device from either the {Env.appName} app or the
        {' ' + Env.appName} command line interface.
      </p>
    </>
  )
}
