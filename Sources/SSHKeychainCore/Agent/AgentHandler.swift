import Foundation
import NIOCore

/// NIO inbound handler that processes SSH-agent protocol frames on a single
/// connection. Each accepted connection gets its own handler instance.
///
/// Wire format: every message is a uint32 length followed by `length` bytes
/// (the first byte being the message type). Handler reads bytes into a buffer,
/// frames messages, dispatches to `AgentService`, writes responses.
final class AgentHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let service: AgentService
    private var buffer = ByteBuffer()

    init(service: AgentService) {
        self.service = service
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = self.unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)
        drain(channel: context.channel)
    }

    func channelInactive(context: ChannelHandlerContext) {
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    private func drain(channel: Channel) {
        while buffer.readableBytes >= 4 {
            let lengthPeek = buffer.getInteger(at: buffer.readerIndex, as: UInt32.self) ?? 0
            let messageLength = Int(lengthPeek)
            if buffer.readableBytes < 4 + messageLength { return }
            buffer.moveReaderIndex(forwardBy: 4)
            guard messageLength > 0,
                  let msgType = buffer.readInteger(as: UInt8.self),
                  let payload = buffer.readBytes(length: messageLength - 1)
            else { return }
            handle(type: msgType, payload: Data(payload), channel: channel)
        }
        buffer.discardReadBytes()
    }

    private func handle(type: UInt8, payload: Data, channel: Channel) {
        guard let kind = AgentProtocol.MessageType(rawValue: type) else {
            send(AgentProtocol.encodeFailure(), to: channel)
            return
        }
        let service = self.service
        switch kind {
        case .requestIdentities:
            Task { [self] in
                let identities = await service.currentIdentities()
                let answer = AgentProtocol.IdentitiesAnswer(keys: identities)
                self.send(answer.encode(), to: channel)
            }
        case .signRequest:
            Task { [self] in
                do {
                    let req = try AgentProtocol.parseSignRequest(payload)
                    let blob = try await service.sign(keyBlob: req.keyBlob, data: req.data, flags: req.flags)
                    self.send(AgentProtocol.encodeSignResponse(signatureBlob: blob), to: channel)
                } catch {
                    self.send(AgentProtocol.encodeFailure(), to: channel)
                }
            }
        default:
            // Read-only agent: every other request type fails.
            send(AgentProtocol.encodeFailure(), to: channel)
        }
    }

    private func send(_ data: Data, to channel: Channel) {
        var buf = channel.allocator.buffer(capacity: data.count)
        buf.writeBytes(data)
        // Channel.writeAndFlush is thread-safe; it hops to the channel's event loop internally.
        channel.writeAndFlush(buf, promise: nil)
    }
}
