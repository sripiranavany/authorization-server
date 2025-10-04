FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy and unzip the distribution
COPY target/authorization-server-bin.zip /tmp/authorization-server-bin.zip
RUN apt-get update && apt-get install -y unzip \
    && unzip /tmp/authorization-server-bin.zip -d /app \
    && rm /tmp/authorization-server-bin.zip

# Make the binary executable (if needed)
RUN chmod +x /app/authorization-server/bin/authorization-server

WORKDIR /app/authorization-server

ENTRYPOINT ["bin/authorization-server", "console"]