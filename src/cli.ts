#!/usr/bin/env node

import process from 'node:process';

import { main } from './launcher.js';

process.exitCode = main();
