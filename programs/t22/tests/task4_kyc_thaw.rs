//! Task 4: KYC thaw — unfreezing individual token accounts.
//!
//! Verifies that accounts on a DefaultAccountState(Frozen) mint start frozen,
//! that transfers fail while frozen, and that invoking kyc_thaw allows transfers
//! for the thawed account while strictly keeping newly created accounts frozen
//! (ensuring the global default is never accidentally altered).

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use anchor_spl::token_interface::spl_token_2022::{
    extension::{ExtensionType, StateWithExtensions},
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState},
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
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

fn send_expecting_failure(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) -> String {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => panic!("expected failure, got success"),
        Err(e) => e.meta.logs.join("\n"),
    }
}

fn create_remittance_mint(svm: &mut LiteSVM, payer: &Keypair) -> Keypair {
    let mint = Keypair::new();
    let ix = Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceMint {
            payer: payer.pubkey(),
            mint: mint.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceMint {
            decimals: DECIMALS,
            basis_points: BASIS_POINTS,
            maximum_fee: MAXIMUM_FEE,
            name: "Remittance Dollar".to_owned(),
            symbol: "RUSD".to_owned(),
            uri: "https://example.com/rusd.json".to_owned(),
        }
        .data(),
    };
    send(svm, payer, &[ix], &[&mint]);
    mint
}

fn create_token_account(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, owner: &Pubkey) -> Keypair {
    let ta = Keypair::new();
    let required = ExtensionType::get_required_init_account_extensions(&[ExtensionType::TransferFeeConfig]);
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&required).unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(), &ta.pubkey(), lamports, space as u64, &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, owner).unwrap(),
        ],
        &[&ta],
    );
    ta
}

fn is_frozen(svm: &LiteSVM, account: &Pubkey) -> bool {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    state.base.state == AccountState::Frozen
}

fn kyc_thaw_ix(freeze_authority: &Pubkey, mint: &Pubkey, ta: Pubkey) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::KycThaw {
            token_account: ta,
            mint: *mint,
            freeze_authority: *freeze_authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::KycThaw {}.data(),
    }
}

/// Newly created accounts on a DefaultAccountState(Frozen) mint start frozen.
#[test]
fn new_account_on_frozen_default_mint_starts_frozen() {
    let (mut svm, payer) = setup();
    let mint = create_remittance_mint(&mut svm, &payer);
    let ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    assert!(is_frozen(&svm, &ta.pubkey()), "account must start frozen");
}

/// A frozen account rejects transfers — KYC gate is enforced.
#[test]
fn transfer_fails_on_frozen_account() {
    let (mut svm, payer) = setup();
    let mint = create_remittance_mint(&mut svm, &payer);

    let source_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    // Thaw source only so we can fund it; dest stays frozen.
    send(&mut svm, &payer, &[kyc_thaw_ix(&payer.pubkey(), &mint.pubkey(), source_ta.pubkey())], &[]);
    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &source_ta.pubkey(), &payer.pubkey(), &[], 1_000).unwrap()],
        &[],
    );

    // Destination is still frozen — transfer must fail.
    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferRemittance {
                source: source_ta.pubkey(),
                mint: mint.pubkey(),
                destination: dest_ta.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferRemittance {
                amount: 500,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );
    assert!(
        logs.contains("AccountFrozen") || logs.contains("0x11"),
        "wrong rejection reason: {logs}"
    );
}

/// After kyc_thaw, transfer succeeds on thawed account, and third account remains frozen.
#[test]
fn after_kyc_thaw_transfer_succeeds_and_global_default_unchanged() {
    let (mut svm, payer) = setup();
    let mint = create_remittance_mint(&mut svm, &payer);

    let source_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    assert!(is_frozen(&svm, &source_ta.pubkey()));
    assert!(is_frozen(&svm, &dest_ta.pubkey()));

    // Thaw both accounts via the kyc_thaw instruction.
    for ta in [source_ta.pubkey(), dest_ta.pubkey()] {
        send(&mut svm, &payer, &[kyc_thaw_ix(&payer.pubkey(), &mint.pubkey(), ta)], &[]);
        assert!(!is_frozen(&svm, &ta), "must be thawed after KYC");
    }

    // A third account created AFTER the thaws is still frozen — global default was untouched.
    let third_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    assert!(
        is_frozen(&svm, &third_ta.pubkey()),
        "third account must still be frozen — kyc_thaw only thaws specific accounts"
    );

    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &source_ta.pubkey(), &payer.pubkey(), &[], 2_000).unwrap()],
        &[],
    );

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferRemittance {
                source: source_ta.pubkey(),
                mint: mint.pubkey(),
                destination: dest_ta.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferRemittance {
                amount: 1_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    let dest_acct = svm.get_account(&dest_ta.pubkey()).unwrap();
    let dest_state = StateWithExtensions::<TokenAccountState>::unpack(&dest_acct.data).unwrap();
    assert!(dest_state.base.amount > 0);
}