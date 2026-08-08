using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;

namespace Sufficit.Identity.UI.Management.Clients;

/// <summary>
/// Circuit-safe adapter for the embedded UI. Each operation owns a short DI
/// scope; presentation code never resolves protocol or persistence services.
/// </summary>
public sealed class ManagementClientDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementClientDataSource> logger)
{
    public Task<ManagementDataResult<IReadOnlyList<ManagementClientSummary>>>
        GetClientsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (clients, context) => clients.ListAsync(
                context,
                cancellationToken),
            "Client listing",
            cancellationToken);

    public Task<ManagementDataResult<IReadOnlyList<ManagementClientProfile>>>
        GetClientProfilesAsync(CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.GetProfilesAsync(context, cancellationToken),
            "Client profile listing",
            cancellationToken);

    public Task<ManagementDataResult<IReadOnlyList<ManagementClientAvailableScope>>>
        GetAvailableClientScopesAsync(CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.GetAvailableScopesAsync(context, cancellationToken),
            "Available client scope listing",
            cancellationToken);

    public Task<ManagementDataResult<IReadOnlyList<ManagementClientDraftSummary>>>
        GetClientDraftsAsync(CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.ListAsync(context, cancellationToken),
            "Client draft listing",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClientDraftDetail>>
        CreateClientDraftAsync(
            string profile,
            CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.CreateAsync(profile, context, cancellationToken),
            "Client draft creation",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClientDraftDetail>>
        GetClientDraftAsync(
            Guid id,
            CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.GetAsync(id, context, cancellationToken),
            "Client draft detail",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClientDraftDetail>>
        SaveClientDraftAsync(
            SaveManagementClientDraftCommand command,
            CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.SaveAsync(command, context, cancellationToken),
            "Client draft save",
            cancellationToken);

    public Task<ManagementDataResult<CompleteManagementClientDraftResult>>
        CompleteClientDraftAsync(
            Guid id,
            string version,
            CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            (drafts, context) => drafts.CompleteAsync(id, version, context, cancellationToken),
            "Client draft completion",
            cancellationToken);

    public Task<ManagementDataResult<bool>> AbandonClientDraftAsync(
        Guid id,
        CancellationToken cancellationToken = default) =>
        ExecuteDraftAsync(
            async (drafts, context) =>
            {
                await drafts.AbandonAsync(id, context, cancellationToken);
                return true;
            },
            "Client draft abandonment",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClientDetail>>
        GetClientAsync(
            string id,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (clients, context) => clients.GetByIdAsync(
                id,
                context,
                cancellationToken),
            "Client detail",
            cancellationToken);

    public Task<ManagementDataResult<ManagementClientDetail>>
        CreateClientAsync(
            CreateManagementClientCommand command,
            CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            (clients, context) => clients.CreateAsync(
                command,
                context,
                cancellationToken),
            "Client creation",
            cancellationToken);

    public Task<ManagementDataResult<bool>> DeleteClientAsync(
        string clientId,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            async (clients, context) =>
            {
                await clients.DeleteAsync(
                    clientId,
                    context,
                    cancellationToken);
                return true;
            },
            "Client deletion",
            cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IClientManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var clients = scope.ServiceProvider
                .GetRequiredService<IClientManagementService>();
            var context = await CreateRequestContextAsync();

            return ManagementDataResult<T>.Success(
                await operation(clients, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Invalid,
                exception.Message,
                exception.Field);
        }
        catch (ManagementConflictException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Conflict,
                exception.Message);
        }
        catch (ManagementNotFoundException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.NotFound,
                exception.Message);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui a autoridade necessária.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço demorou mais que o esperado. Tente novamente.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço de identidade não conseguiu concluir a operação.");
        }
    }

    private async Task<ManagementDataResult<T>> ExecuteDraftAsync<T>(
        Func<IClientConfigurationDraftService, ManagementRequestContext, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var drafts = scope.ServiceProvider
                .GetRequiredService<IClientConfigurationDraftService>();
            var context = await CreateRequestContextAsync();

            return ManagementDataResult<T>.Success(
                await operation(drafts, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Invalid,
                exception.Message,
                exception.Field);
        }
        catch (ManagementConflictException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Conflict,
                exception.Message);
        }
        catch (ManagementNotFoundException exception)
        {
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.NotFound,
                exception.Message);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui a autoridade necessária.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço demorou mais que o esperado. Tente novamente.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "{OperationName} failed in the embedded management module.",
                operationName);
            return ManagementDataResult<T>.Failure(
                ManagementDataOutcome.Unavailable,
                "O serviço de identidade não conseguiu concluir a operação.");
        }
    }

    private async Task<ManagementRequestContext> CreateRequestContextAsync()
    {
        var authenticationState =
            await authenticationStateProvider.GetAuthenticationStateAsync();
        var correlationId = Activity.Current?.Id
            ?? $"management-ui-{Guid.NewGuid():N}";

        return new ManagementRequestContext(
            authenticationState.User,
            correlationId);
    }
}

public enum ManagementDataOutcome
{
    Success,
    Invalid,
    Conflict,
    NotFound,
    Forbidden,
    StepUpRequired,
    Unavailable
}

public sealed record ManagementDataResult<T>(
    ManagementDataOutcome Outcome,
    T? Value = default,
    string? ErrorMessage = null,
    string? ErrorField = null,
    IReadOnlyList<string>? ErrorDetails = null)
{
    public bool IsSuccess => Outcome is ManagementDataOutcome.Success;

    public static ManagementDataResult<T> Success(T value) =>
        new(ManagementDataOutcome.Success, value);

    public static ManagementDataResult<T> Failure(
        ManagementDataOutcome outcome,
        string? errorMessage = null,
        string? errorField = null,
        IReadOnlyList<string>? errorDetails = null) =>
        new(
            outcome,
            ErrorMessage: errorMessage,
            ErrorField: errorField,
            ErrorDetails: errorDetails);
}
