# syntax=docker/dockerfile:1
# Test-only image for the conformance seeder; see conformance/README.md.
ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.302
ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.10

FROM ${DOTNET_SDK_IMAGE} AS build
WORKDIR /src/sufficit-identity
COPY . .
RUN dotnet publish conformance/seeder/Sufficit.Identity.Conformance.Seeder.csproj \
      --configuration Release --output /out -p:SufficitUseLocalSui=false

FROM ${DOTNET_RUNTIME_IMAGE}
WORKDIR /app
COPY --from=build /out .
ENTRYPOINT ["dotnet", "Sufficit.Identity.Conformance.Seeder.dll"]
