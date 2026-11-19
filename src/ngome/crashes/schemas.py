"""The crash report the app sends, field by field. Anything else is refused."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from ngome.appstatus.schemas import Build
from ngome.appstatus.versions import MAX_VERSION_LENGTH, VERSION_PATTERN

MAX_REPORT_BYTES = 16 * 1024
MAX_FRAMES = 64

# The error types the app names; any other error is sent as "Other". Never a message.
ErrorType = Literal[
    "TypeError",
    "StateError",
    "RangeError",
    "ArgumentError",
    "FormatException",
    "SqliteException",
    "TimeoutException",
    "FileSystemException",
    "PlatformException",
    "Other",
]
Cpu = Literal["arm64", "arm", "x64", "ia32", "riscv64"]

# An obfuscated release build's frame, reduced to its offset in the app's instructions.
OFFSET_FRAME = r"#\d{2} pc 0x[0-9a-f]{1,16}"
# An unobfuscated build's frame, from our package, another package or the Dart SDK only.
# The function is dotted identifiers (or "<anonymous closure>"), never free text.
_NAME = r"(?:[A-Za-z_$][A-Za-z0-9_$]{0,79}|<anonymous closure>)"
SOURCE_FRAME = (
    rf"#\d{{2}} (?:new )?{_NAME}(?:\.{_NAME}){{0,5}} "
    r"\((?:package:[a-z0-9_]+/[A-Za-z0-9_/.-]{1,160}\.dart|dart:[a-z_]{1,32}"
    r"(?:/[A-Za-z0-9_/.-]{1,160}\.dart)?)(?::\d{1,6}){0,2}\)"
)
FRAME_PATTERN = rf"^(?:{OFFSET_FRAME}|{SOURCE_FRAME})$"

Frame = Annotated[str, StringConstraints(max_length=240, pattern=FRAME_PATTERN)]


class CrashReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    format: Literal[1]
    app: str = Field(max_length=MAX_VERSION_LENGTH, pattern=VERSION_PATTERN)
    build_number: int = Field(ge=0, le=2_147_483_647)
    build: Build
    os: str = Field(pattern=r"^(?:Android|iOS) \d{1,3}$")
    cpu: Cpu
    error: ErrorType
    build_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16,64}$")
    stack: list[Frame] = Field(max_length=MAX_FRAMES)
