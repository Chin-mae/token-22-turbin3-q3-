//! Task 2: transfer_checked_with_fee with dynamic epoch fee computation.
//!
//! Uses transfer_checked_with_fee (not transfer or transfer_checked), computing the
//! fee on-chain via calculate_epoch_fee(current_epoch, amount) rather than caching a rate.

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use anchor_spl::token_interface::spl_token_2022::{
    extension::{
        transfer_fee::{instruction as transfer_fee_ix, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to, thaw_account},
    state::{Account as TokenAccountState, Mint as MintState},
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 250; // 2.5%
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

fn compute_expected_fee(svm: &LiteSVM, mint: &Pubkey, epoch: u64, amount: u64) -> u64 {
    let acct = svm.get_account(mint).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let config = state.get_extension::<TransferFeeConfig>().unwrap();
    config.calculate_epoch_fee(epoch, amount).unwrap()
}

/// Happy path: transfer_remittance computes the fee dynamically from the mint
/// extension at the current epoch and executes transfer_checked_with_fee.
#[test]
fn transfer_remittance_succeeds_with_correct_dynamic_fee() {
    let (mut svm, payer) = setup();
    let mint = create_remittance_mint(&mut svm, &payer);

    let source_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    // Thaw both accounts to allow transfers.
    for ta in [&source_ta.pubkey(), &dest_ta.pubkey()] {
        send(
            &mut svm,
            &payer,
            &[thaw_account(&TOKEN_2022_PROGRAM_ID, ta, &mint.pubkey(), &payer.pubkey(), &[]).unwrap()],
            &[],
        );
    }

    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &source_ta.pubkey(), &payer.pubkey(), &[], 10_000).unwrap()],
        &[],
    );

    let transfer_amount: u64 = 4_000;
    let expected_fee = compute_expected_fee(&svm, &mint.pubkey(), 0, transfer_amount);
    assert!(expected_fee > 0, "fee must be nonzero");

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
                amount: transfer_amount,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    let dest_acct = svm.get_account(&dest_ta.pubkey()).unwrap();
    let dest_state = StateWithExtensions::<TokenAccountState>::unpack(&dest_acct.data).unwrap();
    assert_eq!(dest_state.base.amount, transfer_amount - expected_fee);

    let src_acct = svm.get_account(&source_ta.pubkey()).unwrap();
    let src_state = StateWithExtensions::<TokenAccountState>::unpack(&src_acct.data).unwrap();
    assert_eq!(src_state.base.amount, 10_000 - transfer_amount);
}

/// Negative test: callers cannot pass a mismatched fee to transfer_checked_with_fee.
#[test]
fn transfer_checked_with_fee_rejects_incorrect_fee() {
    let (mut svm, payer) = setup();
    let mint = create_remittance_mint(&mut svm, &payer);

    let source_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let dest_ta = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    for ta in [&source_ta.pubkey(), &dest_ta.pubkey()] {
        send(
            &mut svm,
            &payer,
            &[thaw_account(&TOKEN_2022_PROGRAM_ID, ta, &mint.pubkey(), &payer.pubkey(), &[]).unwrap()],
            &[],
        );
    }

    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &mint.pubkey(), &source_ta.pubkey(), &payer.pubkey(), &[], 10_000).unwrap()],
        &[],
    );

    let transfer_amount: u64 = 4_000;
    let correct_fee = compute_expected_fee(&svm, &mint.pubkey(), 0, transfer_amount);
    let wrong_fee = correct_fee.saturating_sub(1);

    let bad_ix = transfer_fee_ix::transfer_checked_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        &source_ta.pubkey(),
        &mint.pubkey(),
        &dest_ta.pubkey(),
        &payer.pubkey(),
        &[],
        transfer_amount,
        DECIMALS,
        wrong_fee,
    )
    .unwrap();

    let logs = send_expecting_failure(&mut svm, &payer, &[bad_ix], &[]);
    assert!(
        logs.contains("FeeParametersMismatch")
            || logs.contains("0x1779")
            || logs.contains("0x20")
            || logs.contains("does not match expected fee"),
        "wrong rejection reason: {logs}"
    );
}