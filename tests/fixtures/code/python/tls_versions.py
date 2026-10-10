import ssl


def legacy_context() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def legacy_client() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_1
    return context


def sslv3_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.SSLv3
    return context


def tls10_minimum() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1
    return context


def modern_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return context


def negotiate_best() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_SSLv23)
