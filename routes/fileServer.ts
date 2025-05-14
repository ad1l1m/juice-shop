/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'
import challengeUtils = require('../lib/challengeUtils')

import * as utils from '../lib/utils'
import { partial_ratio } from 'fuzzball'
const security = require('../lib/insecurity')

module.exports = function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    let file = params.file

    if (file.includes('/')) {
      res.status(403)
      return next(new Error('File names cannot contain forward slashes!'))
    }

    file = decodeURIComponent(file)

    if (file && (endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
    file = security.cutOffPoisonNullByte(file)
    verifySuccessfulPoisonNullByteExploit(file)

    const baseDir = path.resolve('ftp/')
    const requestedPath = path.resolve(baseDir, file)

    // Semgrep любит эту проверку
    if (!requestedPath.startsWith(baseDir + path.sep)) {
      return res.status(403).send('Access denied')
    }

    return res.sendFile(requestedPath)
  } else {
    res.status(403)
    next(new Error('Only .md and .pdf files are allowed!'))
  }
  }



  function verifySuccessfulPoisonNullByteExploit (file: string) {
    console.log(file, 'third file')
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    console.log(param, 'fourth file or console')
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
