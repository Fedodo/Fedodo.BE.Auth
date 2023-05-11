FROM mcr.microsoft.com/dotnet/aspnet:7.0-alpine AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0-alpine AS build
WORKDIR /src
COPY ["Fedodo.BE.Auth/Fedodo.BE.Auth.csproj", "Fedodo.BE.Auth/"]
RUN dotnet restore "Fedodo.BE.Auth/Fedodo.BE.Auth.csproj"
COPY . .
WORKDIR "/src/Fedodo.BE.Auth"
RUN dotnet build "Fedodo.BE.Auth.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Fedodo.BE.Auth.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Fedodo.BE.Auth.dll"]
