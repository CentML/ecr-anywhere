/*
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
*/
package loggers

import "log"

// loggers contains the loggers for info and error messages.
type Loggers struct {
	InfoLogger  *log.Logger
	WarnLogger  *log.Logger
	ErrorLogger *log.Logger
}

// NewLoggers creates a new Loggers object with the specified loggers for
// info, warn and error messages.
func NewLoggers(infoLogger, warnLogger, errorLogger *log.Logger) *Loggers {
	return &Loggers{
		InfoLogger:  infoLogger,
		WarnLogger:  warnLogger,
		ErrorLogger: errorLogger,
	}
}
