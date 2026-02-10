def get_client_ip(request):
    """
    Returns the real client IP address even behind Render / proxies
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs
        # Client IP is always the FIRST one
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip
