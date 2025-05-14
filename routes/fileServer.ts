/*
 * Copyright (c) 2014‑2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX‑License‑Identifier: MIT
 */

import path = require('path')
import { Request, Response, NextFunction } from 'express'
import { challenges } from '../data/datacache'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')

module.exports = function servePublicFiles () {
  /* ───────── вспомогательные ───────── */
  function endsWithAllowlistedFileType (p: string) {
    return utils.endsWith(p, '.md') || utils.endsWith(p, '.pdf')
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge,      () => file.toLowerCase() === 'eastere.gg')
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge,     () => file.toLowerCase() === 'package.json.bak')
    challengeUtils.solveIf(challenges.forgottenBackupChallenge,        () => file.toLowerCase() === 'coupons_2013.md.bak')
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => file.toLowerCase() === 'suspicious_errors.yml')
    challengeUtils.solveIf(challenges.nullByteChallenge, () =>
      challenges.easterEggLevelOneChallenge.solved      ||
      challenges.forgottenDevBackupChallenge.solved     ||
      challenges.forgottenBackupChallenge.solved        ||
      challenges.misplacedSignatureFileChallenge.solved ||
      file.toLowerCase() === 'encrypt.pyc')
  }

  /* ───────── основной обработчик ───────── */
  return ({ params }: Request, res: Response, _next: NextFunction) => {
    let file = params.file

    /* 1. базовая валидация имени */
    if (file.includes('/') || file.includes('..') || path.isAbsolute(file)) {
      return res.status(403).send('Invalid file name')
    }
    file = decodeURIComponent(file)

    /* 2. проверка расширения */
    if (!(endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
      return res.status(403).send('Only .md and .pdf files are allowed')
    }

    file = security.cutOffPoisonNullByte(file)
    verifySuccessfulPoisonNullByteExploit(file)

    /* 3. безопасное формирование пути */
    const baseDir  = path.resolve('ftp')     // …/ftp
    const safeName = path.basename(file)     // <file>

    if (safeName !== file) {           // теоретически вдруг что‑то изменилось
      return res.status(403).send('Invalid file name')
    }


    const requested = path.join(baseDir, safeName)
    if (path.relative(baseDir, requested).startsWith('..')) {
      return res.status(403).send('Access denied')
    }

    /* 4. отдаём файл */
    return res.sendFile(safeName, { root: baseDir, dotfiles: 'deny' })
  }
}
