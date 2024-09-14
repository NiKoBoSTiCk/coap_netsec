import aiocoap
import asyncio

SERVER_IP = 'localhost'
SERVER_PORT = 5683


class CoAPController:
    def __init__(self):
        self.protocol = None
        self.security_level = 1

    async def run(self):
        self.protocol = await aiocoap.Context.create_client_context()

        while True:
            print("\nChoose a security level:")
            print("0. Exit")
            print("1. Confidentiality")
            print("2. Integrity")
            print("3. Authentication")

            choice = input("Enter the security level: ")

            if choice in ['1', '2', '3']:
                self.security_level = int(choice)
                print(f"Setting security level to: {self.security_level}")
                await self._send_security_level()
            elif choice == '0':
                print("Exiting controller.")
                break
            else:
                print("Invalid choice. Please try again.")


    async def _send_security_level(self):
        request = aiocoap.Message(
            code=aiocoap.Code.PUT,
            uri=f'coap://{SERVER_IP}:{SERVER_PORT}/security_level',
            payload=str(self.security_level).encode()
        )
        try:
            response = await self.protocol.request(request).response
            print(f"Server response: {response.payload.decode()}")
        except Exception as e:
            print(f"Failed to set security level: {e}")


if __name__ == "__main__":
    controller = CoAPController()
    asyncio.get_event_loop().run_until_complete(controller.run())
