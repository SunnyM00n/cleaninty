from struct import pack, unpack
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from . import certificate
from ..common import digitalsignature as digsign
from . import otp
from .exception import ClassInitError

__all__ = [
	"APCert"
]

class APCert(certificate.Certificate):
	def __init__(self, ngcert: otp.NGCert, titleid: typing.SupportsInt):
		if not isinstance(ngcert, otp.NGCert):
			raise ClassInitError("APCert excepts NGCert object")

		titleid = int(titleid)

		if titleid < 0 or (titleid & 0xFFFF000000000000) != 0x0005000000000000:
			raise ClassInitError("Invalid titleid")

		try:
			privkey = ec.generate_private_key(ec.SECT233R1(), default_backend())
			pubkeynumbers = privkey.public_key().public_numbers()
		except Exception as e:
			raise ClassInitError("EC Key generation error") from e

		try:
			data = pack(
				">I60x64x64sI64sI30s30s60x",
				digsign.SignatureType.ECC_SHA256,
				b"SigningStaging",
				digsign.KeyType.ECC,
				(f"AP{titleid:016x}").encode(),
				0,
				pubkeynumbers.x.to_bytes(30, 'big'),
				pubkeynumbers.y.to_bytes(30, 'big')
			)
		except Exception as e:
			raise ClassInitError("Packing error") from e

		super().__init__(data)

		try:
			self.reissue(ngcert)
			self.verify(ngcert)
		except Exception as e:
			raise ClassInitError("Could not sign or verify the generated APCert") from e

		if not self.set_private_key(privkey.private_numbers()):
			raise ClassInitError("APCert private key was not successfully loaded!")

		self._ap_title_id = titleid

	@property
	def ap_title_id(self) -> int:
		return self._ap_title_id
