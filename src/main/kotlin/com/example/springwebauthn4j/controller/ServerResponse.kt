package com.example.springwebauthn4j.controller

import com.example.springwebauthn4j.service.Status

open class ServerResponse(
    var status: Status,
    var errorMessage: String,
)
