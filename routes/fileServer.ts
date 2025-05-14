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
    let file = params.file;

    /* ---------- 1. Базовая валидация ---------- */
    if (file.includes('/') || file.includes('..') || path.isAbsolute(file)) {
      return res.status(403).send('Invalid file name');
    }
    file = decodeURIComponent(file);

    /* ---------- 2. Разрешённые расширения ---------- */
    if (!(endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
      return res.status(403).send('Only .md and .pdf files are allowed');
    }

    file = security.cutOffPoisonNullByte(file);
    verifySuccessfulPoisonNullByteExploit(file);

    /* ---------- 3. Построение и КРИТИЧЕСКАЯ проверка пути ---------- */
    const baseDir = path.resolve('ftp');             // …/ftp
    const requestedPath = path.resolve(baseDir, file); // …/ftp/<file>

    // Semgrep “любит” именно такое сравнение
    if (path.relative(baseDir, requestedPath).startsWith('..')) {
      return res.status(403).send('Access denied');
    }

    /* ---------- 4. Отдаём файл ---------- */
    return res.sendFile(requestedPath);
  };

  /* --- вспомогательные функции (без изменений) --- */
  function verifySuccessfulPoisonNullByteExploit (file: string) { /* … */ }
  function endsWithAllowlistedFileType (p: string) {
    return utils.endsWith(p, '.md') || utils.endsWith(p, '.pdf');
  }
};




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

