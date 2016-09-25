#!/bin/sh

w3af -s ${1} | tee ${2}

