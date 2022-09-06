use std::path::Path;

use samply_symbols::{
    debug_id_for_object,
    debugid::DebugId,
    object::{
        self, macho::FatHeader, read::macho::FatArch, Architecture, CompressionFormat, File,
        FileKind, Object,
    },
    relative_address_base, CandidatePathInfo, FileAndPathHelper, FileAndPathHelperError,
    FileContentsWrapper, FileLocation,
};
use serde_json::json;
use yaxpeax_arch::{Arch, DecodeError, U8Reader};

use crate::asm::response_json::DecodedInstruction;

mod request_json;
mod response_json;

#[derive(thiserror::Error, Debug)]
enum AsmError {
    #[error("Couldn't parse request: {0}")]
    ParseRequestErrorSerde(#[from] serde_json::error::Error),

    #[error("Invalid breakpad ID {0}")]
    InvalidBreakpadId(String),

    #[error("An error occurred when obtaining the binary: {0}")]
    FileAndPathHelperError(#[from] FileAndPathHelperError),

    // #[error("Don't have the requested binary")]
    // NoBinary,
    #[error("The debug ID of the object could not be read")]
    NoDebugId,

    #[error("The debug ID of the object did not match. Expected: {0}, got: {1}")]
    UnmatchedDebugId(DebugId, DebugId),

    #[error("open_file helper callback for file {0} returned error: {1}")]
    HelperErrorDuringOpenFile(String, #[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Dyld cache parsing error: {0}")]
    DyldCacheParseError(#[source] object::read::Error),

    #[error("The dyld shared cache file did not include an entry for the dylib at {0}")]
    NoMatchingDyldCacheImagePath(String),

    #[error("MachOHeader parsing error: {0}")]
    MachOHeaderParseError(#[source] object::read::Error),

    #[error("object parse error: {0}")]
    ObjectParseError(#[from] object::Error),

    #[error("The requested address was not found in any section in the binary.")]
    AddressNotFound,

    #[error("Unexpected compression of text section")]
    UnexpectedCompression,

    #[error("Could not read the requested address range from the section (might be out of bounds or the section might not have any bytes in the file)")]
    ByteRangeNotInSection,

    #[error("Unrecognized architecture {0:?}")]
    UnrecognizedArch(Architecture),

    #[error("No candidate path for binary, for {0} {1}")]
    NoCandidatePathForBinary(String, DebugId),
}

#[derive(Clone, Debug, Default)]
struct Query {
    debug_id: DebugId,
    start_address: u32,
    size: u32,
}

pub async fn query_api_json<'h>(
    request_json: &str,
    helper: &'h impl FileAndPathHelper<'h>,
) -> String {
    match query_api_fallible_json(request_json, helper).await {
        Ok(response_json) => response_json,
        Err(err) => json!({ "error": err.to_string() }).to_string(),
    }
}

async fn query_api_fallible_json<'h>(
    request_json: &str,
    helper: &'h impl FileAndPathHelper<'h>,
) -> Result<String, AsmError> {
    let request: request_json::Request = serde_json::from_str(request_json)?;
    let response = query_api(&request, helper).await?;
    Ok(serde_json::to_string(&response)?)
}

async fn query_api<'h>(
    request: &request_json::Request,
    helper: &'h impl FileAndPathHelper<'h>,
) -> Result<response_json::Response, AsmError> {
    let request_json::Request {
        debug_id,
        debug_name,
        // name,
        // code_id,
        start_address,
        size,
        ..
    } = request;

    let (debug_name, debug_id) = match debug_name {
        Some(debug_name) => {
            let debug_id = DebugId::from_breakpad(debug_id)
                .map_err(|_| AsmError::InvalidBreakpadId(debug_id.clone()))?;
            (debug_name, debug_id)
        }
        _ => todo!(),
    };

    let candidate_paths_for_binary =
        helper.get_candidate_paths_for_binary_or_pdb(debug_name, &debug_id)?;

    let query = Query {
        debug_id,
        start_address: *start_address,
        size: *size,
    };

    let mut last_err = None;
    for candidate_info in candidate_paths_for_binary {
        let result = match candidate_info {
            CandidatePathInfo::SingleFile(file_location) => {
                do_stuff_at_path(&file_location, &query, helper).await
            }
            CandidatePathInfo::InDyldCache {
                dyld_cache_path,
                dylib_path,
            } => {
                with_dyld_shared_cache(&dyld_cache_path, &dylib_path, helper, |object, _, _| {
                    do_stuff_with_object(object, &query)
                })
                .await
            }
        };

        match result {
            Ok(result) => return Ok(result),
            Err(err) => last_err = Some(err),
        };
    }
    Err(last_err
        .unwrap_or_else(|| AsmError::NoCandidatePathForBinary(debug_name.clone(), debug_id)))
}

async fn with_dyld_shared_cache<'h, R, H, F>(
    dyld_cache_path: &Path,
    dylib_path: &str,
    helper: &'h H,
    callback: F,
) -> Result<R, AsmError>
where
    H: FileAndPathHelper<'h>,
    F: FnOnce(
        &object::File<'_, &FileContentsWrapper<H::F>>,
        &FileContentsWrapper<H::F>,
        u64,
    ) -> Result<R, AsmError>,
{
    let get_file = |path| helper.open_file(&FileLocation::Path(path));

    let root_contents = get_file(dyld_cache_path.into()).await.map_err(|e| {
        AsmError::HelperErrorDuringOpenFile(dyld_cache_path.to_string_lossy().to_string(), e)
    })?;
    let root_contents = FileContentsWrapper::new(root_contents);

    let dyld_cache_path = dyld_cache_path.to_string_lossy();

    let mut subcache_contents = Vec::new();
    for subcache_index in 1.. {
        // Find the subcache at dyld_shared_cache_arm64e.1 or dyld_shared_cache_arm64e.01
        let subcache_path = format!("{}.{}", dyld_cache_path, subcache_index);
        let subcache_path2 = format!("{}.{:02}", dyld_cache_path, subcache_index);
        let subcache = match get_file(subcache_path.into()).await {
            Ok(subcache) => subcache,
            Err(_) => match get_file(subcache_path2.into()).await {
                Ok(subcache) => subcache,
                Err(_) => break,
            },
        };
        subcache_contents.push(FileContentsWrapper::new(subcache));
    }
    let symbols_subcache_path = format!("{}.symbols", dyld_cache_path);
    if let Ok(subcache) = get_file(symbols_subcache_path.into()).await {
        subcache_contents.push(FileContentsWrapper::new(subcache));
    };

    let subcache_contents_refs: Vec<&FileContentsWrapper<H::F>> =
        subcache_contents.iter().collect();
    let cache = object::read::macho::DyldCache::<object::Endianness, _>::parse(
        &root_contents,
        &subcache_contents_refs,
    )
    .map_err(AsmError::DyldCacheParseError)?;
    let image = match cache.images().find(|image| image.path() == Ok(dylib_path)) {
        Some(image) => image,
        None => {
            return Err(AsmError::NoMatchingDyldCacheImagePath(
                dylib_path.to_string(),
            ))
        }
    };

    let object = image
        .parse_object()
        .map_err(AsmError::MachOHeaderParseError)?;

    let (data, header_offset) = image
        .image_data_and_offset()
        .map_err(AsmError::MachOHeaderParseError)?;
    callback(&object, data, header_offset)
}

async fn do_stuff_at_path<'h>(
    location: &FileLocation,
    query: &Query,
    helper: &'h impl FileAndPathHelper<'h>,
) -> Result<response_json::Response, AsmError> {
    let file_contents = helper.open_file(location).await?;
    let file_contents = FileContentsWrapper::new(file_contents);
    match File::parse(&file_contents) {
        Ok(file) => do_stuff_with_object(&file, query),
        Err(e) => {
            let fat_arch_ranges: Vec<_> = match FileKind::parse(&file_contents)? {
                FileKind::MachOFat32 => FatHeader::parse_arch32(&file_contents)?
                    .iter()
                    .map(FatArch::file_range)
                    .collect(),
                FileKind::MachOFat64 => FatHeader::parse_arch64(&file_contents)?
                    .iter()
                    .map(FatArch::file_range)
                    .collect(),
                _ => return Err(e.into()),
            };

            let mut last_error = None;

            for (start, size) in fat_arch_ranges {
                let file = File::parse(file_contents.range(start, size))
                    .map_err(AsmError::MachOHeaderParseError)?;
                match do_stuff_with_object(&file, query) {
                    Ok(res) => return Ok(res),
                    Err(err) => last_error = Some(err),
                }
            }
            Err(last_error.unwrap())
        }
    }
}

fn do_stuff_with_object<'data: 'file, 'file>(
    object: &'file impl Object<'data, 'file>,
    query: &Query,
) -> Result<response_json::Response, AsmError> {
    let debug_id = debug_id_for_object(object).ok_or(AsmError::NoDebugId)?;
    if debug_id != query.debug_id {
        return Err(AsmError::UnmatchedDebugId(debug_id, query.debug_id));
    }

    // Align the start address, for architectures with instruction alignment.
    // For example, on ARM, you might be looking for the instructions of a
    // function whose function symbol has address 0x2001. But this address is
    // really two pieces of information: 0x2000 is the address of the function's
    // first instruction (ARM instructions are two-byte aligned), and the 0x1 bit
    // is the "thumb" bit, meaning that the instructions need to be decoded
    // with the thumb decoder.
    let architecture = object.architecture();
    let relative_start_address = match architecture {
        Architecture::Aarch64 => query.start_address & !0b11,
        Architecture::Arm => query.start_address & !0b1,
        _ => query.start_address,
    };

    // Translate start_address from a "relative address" into an
    // SVMA ("stated virtual memory address").
    let image_base = relative_address_base(object);
    let start_address = image_base + u64::from(relative_start_address);

    // Find the section which contains our start_address.
    use object::ObjectSection;
    let (section, section_address_range) = object
        .sections()
        .find_map(|section| {
            let section_start_addr = section.address();
            let section_end_addr = section_start_addr.checked_add(section.size())?;
            let address_range = section_start_addr..section_end_addr;
            if !address_range.contains(&start_address) {
                return None;
            }

            Some((section, address_range))
        })
        .ok_or(AsmError::AddressNotFound)?;

    let file_range = section.compressed_file_range()?;
    if file_range.format != CompressionFormat::None {
        return Err(AsmError::UnexpectedCompression);
    }

    // Pad out the number of bytes we read a little, to allow for reading one
    // more instruction.
    // We've been asked to decode the instructions whose instruction addresses
    // are in the range start_address .. (start_address + size). If the end of
    // this range points into the middle of an instruction, we still want to
    // decode the entire instruction last, so we need all of its bytes.
    // We have another check later to make sure we don't return instructions whose
    // address is beyond the requested range.
    const MAX_INSTR_LEN: u64 = 15; // TODO: Get the correct max length for this arch
    let max_read_len = section_address_range.end - start_address;
    let read_len = (u64::from(query.size) + MAX_INSTR_LEN).min(max_read_len);

    // Now read the instruction bytes from the file.
    let bytes = section
        .data_range(start_address, read_len)?
        .ok_or(AsmError::ByteRangeNotInSection)?;

    let reader = yaxpeax_arch::U8Reader::new(bytes);
    let (instructions, len) = decode_arch(reader, architecture, query.size)?;
    Ok(response_json::Response {
        start_address: relative_start_address,
        size: len,
        instructions,
    })
}

fn decode_arch(
    reader: U8Reader,
    arch: Architecture,
    decode_len: u32,
) -> Result<(Vec<DecodedInstruction>, u32), AsmError> {
    Ok(match arch {
        Architecture::I386 => decode::<yaxpeax_x86::protected_mode::Arch>(reader, decode_len),
        Architecture::X86_64 => decode::<yaxpeax_x86::amd64::Arch>(reader, decode_len),
        Architecture::Aarch64 => decode::<yaxpeax_arm::armv8::a64::ARMv8>(reader, decode_len),
        Architecture::Arm => decode::<yaxpeax_arm::armv7::ARMv7>(reader, decode_len),
        _ => return Err(AsmError::UnrecognizedArch(arch)),
    })
}

trait InstructionDecoding: Arch {
    fn make_decoder() -> Self::Decoder;
    fn stringify_inst(inst: Self::Instruction) -> String;
}

impl InstructionDecoding for yaxpeax_x86::amd64::Arch {
    fn make_decoder() -> Self::Decoder {
        yaxpeax_x86::amd64::InstDecoder::default()
    }

    fn stringify_inst(inst: Self::Instruction) -> String {
        inst.to_string()
    }
}

impl InstructionDecoding for yaxpeax_x86::protected_mode::Arch {
    fn make_decoder() -> Self::Decoder {
        yaxpeax_x86::protected_mode::InstDecoder::default()
    }

    fn stringify_inst(inst: Self::Instruction) -> String {
        inst.to_string()
    }
}

impl InstructionDecoding for yaxpeax_arm::armv8::a64::ARMv8 {
    fn make_decoder() -> Self::Decoder {
        yaxpeax_arm::armv8::a64::InstDecoder::default()
    }

    fn stringify_inst(inst: Self::Instruction) -> String {
        inst.to_string()
    }
}

impl InstructionDecoding for yaxpeax_arm::armv7::ARMv7 {
    fn make_decoder() -> Self::Decoder {
        // TODO: Detect whether the instructions in the requested address range
        // use thumb or non-thumb mode.
        // I'm not quite sure how to do this. The same object file can contain both
        // types of code in different functions. We basically have two options:
        //  1. Have the API caller tell us whether to use thumb, or
        //  2. Detect the mode based on the content in the file.
        // For 2., we could look up the closest symbol to the start address and
        // check whether its symbol address has the thumb bit set. But the function
        // may not have a symbol in the binary that we have access to here.
        //
        // For now we just always assume thumb.
        yaxpeax_arm::armv7::InstDecoder::default_thumb()
    }

    fn stringify_inst(inst: Self::Instruction) -> String {
        inst.to_string()
    }
}

fn decode<'a, A: InstructionDecoding>(
    mut reader: U8Reader<'a>,
    decode_len: u32,
) -> (Vec<DecodedInstruction>, u32)
where
    u64: From<A::Address>,
    U8Reader<'a>: yaxpeax_arch::Reader<A::Address, A::Word>,
{
    use yaxpeax_arch::Decoder;
    let decoder = A::make_decoder();
    let mut instructions = Vec::new();
    loop {
        let offset = u64::from(yaxpeax_arch::Reader::<A::Address, A::Word>::total_offset(
            &mut reader,
        )) as u32;
        if offset >= decode_len {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let decoded_string = A::stringify_inst(inst);
                instructions.push(DecodedInstruction {
                    offset,
                    decoded_string,
                });
            }
            Err(e) => {
                if !e.data_exhausted() {
                    // If decoding encountered an error, append a fake "!!! ERROR" instruction
                    instructions.push(DecodedInstruction {
                        offset,
                        decoded_string: format!("!!! ERROR: {}", e),
                    });
                }
                break;
            }
        }
    }
    let final_offset = u64::from(yaxpeax_arch::Reader::<A::Address, A::Word>::total_offset(
        &mut reader,
    )) as u32;

    (instructions, final_offset)
}
