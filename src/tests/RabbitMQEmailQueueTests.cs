using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core;
using Sufficit.Identity.STS.Email;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class RabbitMQEmailQueueTests
{
    [Fact]
    public async Task Password_reset_preserves_q_email_contract_and_test_recipient_override()
    {
        var publisher = new CapturingPublisher();
        var queue = new RabbitMQEmailQueue(
            publisher,
            NullLogger<RabbitMQEmailQueue>.Instance,
            new EmailOptions { TestEmailAddress = "safe@example.test" });

        await queue.SendEmailAsync(
            "real@example.test",
            "Reset your password",
            "<a href=\"https://identity.test/reset\">continue</a>");

        var message = Assert.IsType<EmailQueueMessage>(publisher.Message);
        Assert.Equal("EMAIL", message.Type);
        Assert.NotEqual(Guid.Empty, message.Id);
        Assert.Equal(RabbitMQEmailQueue.PasswordResetModelId, message.ModelId);
        Assert.Equal("safe@example.test", message.Recipient);
        Assert.Equal("Reset your password", message.Subject);
        Assert.True(message.Trackable);
        Assert.Equal(
            "<a href=\"https://identity.test/reset\">continue</a>",
            Encoding.UTF8.GetString(message.Body));

        using var json = JsonDocument.Parse(RabbitMqEmailPublisher.Serialize(message));
        var root = json.RootElement;
        Assert.Equal("EMAIL", root.GetProperty("type").GetString());
        Assert.Equal(message.Id, root.GetProperty("id").GetGuid());
        Assert.Equal(message.ModelId, root.GetProperty("modelid").GetGuid());
        Assert.Equal(message.Recipient, root.GetProperty("recipient").GetString());
        Assert.Equal(message.Subject, root.GetProperty("subject").GetString());
        Assert.True(root.GetProperty("trackable").GetBoolean());
        Assert.Equal(Convert.ToBase64String(message.Body), root.GetProperty("body").GetString());
    }

    private sealed class CapturingPublisher : IEmailMessagePublisher
    {
        public EmailQueueMessage? Message { get; private set; }

        public Task PublishAsync(EmailQueueMessage message, CancellationToken cancellationToken)
        {
            Message = message;
            return Task.CompletedTask;
        }
    }
}
