//! Task 5: Re-issued mint v2 stacking extensions with manual approval policy.
//!
//! Validates:
//! 1. All extensions from Task 1 + PermanentDelegate + ConfidentialTransferMint (and required
//!    ConfidentialTransferFeeConfig) are stacked with precise account sizing via
//!    ExtensionType::try_calculate_account_len
//! 2. Every extension initialization is executed before InitializeMint2
//! 3. auto_approve_new_accounts = false requires explicit issuer approval (approve_confidential_account)
//! 4. PermanentDelegate allows issuer/delegate to move tokens without holder signature

use std::num::NonZeroI8;
use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use proofext::instruction::ProofLocation;
use t22new::{
    extension::{
        confidential_transfer::{
            instruction as ct_ix, ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        permanent_delegate::PermanentDelegate,
        transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to, thaw_account},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use zk::{
    encryption::derivation::derive_confidential_keys,
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 2;
const BASIS_POINTS: u16 = 250;
const MAXIMUM_FEE: u64 = 1_000;

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    svm.add_program_from_file(ID, path).unwrap();
    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    if let Err(e) = svm.send_transaction(tx) {
        panic!("tx failed: {:#?}", e.meta.logs);
    }
}

/// Create the v2 re-issued mint with extensions stacked and manual approval policy.
fn create_v2_mint(svm: &mut LiteSVM, payer: &Keypair, auto_approve: bool) -> Keypair {
    let mint = Keypair::new();
    let (elgamal, _) = derive_confidential_keys(payer, b"").unwrap();
    let fee_pk: [u8; 32] = elgamal.pubkey().into();

    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceMintV2 {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceMintV2 {
            decimals: DECIMALS,
            basis_points: BASIS_POINTS,
            maximum_fee: MAXIMUM_FEE,
            auto_approve_new_accounts: auto_approve,
            withdraw_withheld_authority_elgamal_pubkey: fee_pk,
        }
        .data(),
    };
    send(svm, payer, &[ix], &[&mint]);
    mint
}

#[test]
fn remittance_mint_v2_stacks_extensions_correctly() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer, false);

    let account = svm.get_account(&mint.pubkey()).unwrap();
    let expected_len = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::TransferFeeConfig,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ])
    .unwrap();
    assert_eq!(account.data.len(), expected_len);

    let state = StateWithExtensions::<MintState>::unpack(&account.data).unwrap();
    assert_eq!(state.base.decimals, DECIMALS);

    let types = state.get_extension_types().unwrap();
    assert_eq!(
        types,
        vec![
            ExtensionType::MintCloseAuthority,
            ExtensionType::PermanentDelegate,
            ExtensionType::MetadataPointer,
            ExtensionType::DefaultAccountState,
            ExtensionType::TransferFeeConfig,
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
        ]
    );

    // 1. Close authority
    let close = state.get_extension::<MintCloseAuthority>().unwrap();
    assert_eq!(Option::<Pubkey>::from(close.close_authority), Some(payer.pubkey()));

    // 2. Permanent delegate
    let pd = state.get_extension::<PermanentDelegate>().unwrap();
    assert_eq!(Option::<Pubkey>::from(pd.delegate), Some(payer.pubkey()));

    // 3. Metadata pointer
    let pointer = state.get_extension::<MetadataPointer>().unwrap();
    assert_eq!(Option::<Pubkey>::from(pointer.metadata_address), Some(mint.pubkey()));

    // 4. Default account state
    let default_state = state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(default_state.state, AccountState::Frozen as u8);

    // 5. Transfer fee config
    let fee = state.get_extension::<TransferFeeConfig>().unwrap();
    assert_eq!(u16::from(fee.newer_transfer_fee.transfer_fee_basis_points), BASIS_POINTS);

    // 6. Confidential transfer mint: manual approval
    let ct = state.get_extension::<ConfidentialTransferMint>().unwrap();
    assert_eq!(Option::<Pubkey>::from(ct.authority), Some(payer.pubkey()));
    assert_eq!(bool::from(ct.auto_approve_new_accounts), false);

    // 7. Confidential transfer fee config
    let _ctf = state.get_extension::<ConfidentialTransferFeeConfig>().unwrap();
}

#[test]
fn manual_approval_policy_requires_issuer_approval() {
    let (mut svm, payer) = setup();
    // Create mint with manual approve policy (auto_approve = false)
    let mint = create_v2_mint(&mut svm, &payer, false);

    let user = Keypair::new();
    svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();

    let user_ta = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::ConfidentialTransferFeeAmount,
    ])
    .unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &user_ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &user_ta.pubkey(), &mint.pubkey(), &user.pubkey()).unwrap(),
        ],
        &[&user_ta],
    );

    // Thaw the account from default frozen state
    send(
        &mut svm,
        &payer,
        &[thaw_account(&TOKEN_2022_PROGRAM_ID, &user_ta.pubkey(), &mint.pubkey(), &payer.pubkey(), &[]).unwrap()],
        &[],
    );

    // Configure the account for confidential transfers
    let (elgamal, aes) = derive_confidential_keys(&user, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let config_ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &user_ta.pubkey(),
        &mint.pubkey(),
        &aes.encrypt(0).into(),
        65536,
        &user.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(&mut svm, &user, &config_ixs, &[]);

    // Verify: Because auto_approve = false, approved is FALSE initially!
    let acct = svm.get_account(&user_ta.pubkey()).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let ct_acct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
    assert_eq!(bool::from(ct_acct.approved), false, "account must not be auto-approved");

    // Issuer approves via approve_confidential_account
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApproveConfidentialAccount {
                token_account: user_ta.pubkey(),
                mint: mint.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApproveConfidentialAccount {}.data(),
        }],
        &[],
    );

    // Verify: Now approved is TRUE!
    let acct_after = svm.get_account(&user_ta.pubkey()).unwrap();
    let state_after = StateWithExtensions::<TokenAccountState>::unpack(&acct_after.data).unwrap();
    let ct_after = state_after.get_extension::<ConfidentialTransferAccount>().unwrap();
    assert_eq!(bool::from(ct_after.approved), true, "account must be approved after issuer call");
}

#[test]
fn permanent_delegate_can_seize_on_v2_mint() {
    let (mut svm, payer) = setup();
    let mint = create_v2_mint(&mut svm, &payer, false);

    let user = Keypair::new();
    let user_ta = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
    ])
    .unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &user_ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &user_ta.pubkey(), &mint.pubkey(), &user.pubkey()).unwrap(),
            thaw_account(&TOKEN_2022_PROGRAM_ID, &user_ta.pubkey(), &mint.pubkey(), &payer.pubkey(), &[]).unwrap(),
            mint_to(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &user_ta.pubkey(), &payer.pubkey(), &[], 5_000).unwrap(),
        ],
        &[&user_ta],
    );

    let dest_ta = Keypair::new();
    send(
        &mut svm,
        &payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &dest_ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &dest_ta.pubkey(), &mint.pubkey(), &payer.pubkey()).unwrap(),
            thaw_account(&TOKEN_2022_PROGRAM_ID, &dest_ta.pubkey(), &mint.pubkey(), &payer.pubkey(), &[]).unwrap(),
        ],
        &[&dest_ta],
    );

    // Permanent delegate seizes 2_000 tokens without user signing!
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::PermanentDelegateSeize {
                source: user_ta.pubkey(),
                mint: mint.pubkey(),
                destination: dest_ta.pubkey(),
                permanent_delegate: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::PermanentDelegateSeize {
                amount: 2_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    let user_acct = svm.get_account(&user_ta.pubkey()).unwrap();
    let user_state = StateWithExtensions::<TokenAccountState>::unpack(&user_acct.data).unwrap();
    assert_eq!(user_state.base.amount, 3_000);
}