FROM php:8.2-apache

# SQLite3 extension for the vulnerable DB layer
RUN apt-get update && apt-get install -y libsqlite3-dev \
    && docker-php-ext-install pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

# Enable mod_headers (for the deliberately-insecure Set-Cookie) and .htaccess
RUN a2enmod headers && a2enmod rewrite
RUN sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Deliberately expose server tokens (Server / X-Powered-By) for passive disclosure findings
RUN echo "ServerTokens Full\nServerSignature On" >> /etc/apache2/apache2.conf

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod 777 /tmp

EXPOSE 80
