FROM node:20

WORKDIR /app
COPY . .
RUN npm install

# DEFECT (runs as root): no USER directive, so the process has root inside the
# container.
# DEFECT (no healthcheck): the orchestrator cannot tell a hung process from a
# healthy one.
# DEFECT (secrets in image): the committed .env is copied in by `COPY . .`.
EXPOSE 3000
CMD ["npm", "start"]
