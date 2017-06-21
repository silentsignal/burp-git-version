package burp;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.stream.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Frame;
import java.awt.event.*;
import javax.swing.*;

import org.eclipse.jgit.api.*;
import org.eclipse.jgit.api.errors.*;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.storage.file.*;
import org.eclipse.jgit.revwalk.*;
import org.eclipse.jgit.treewalk.*;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	private IExtensionHelpers helpers;
	private OutputStream stderr;
	private final static String NAME = "Git version"; // FIXME
	private static File lastGitDir = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		stderr = callbacks.getStderr();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Find version from git"); // FIXME
		i.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				// src: https://coderanch.com/t/346777/java/parent-frame-JMenuItem-ActionListener
				JMenuItem menuItem = (JMenuItem)event.getSource();
				JPopupMenu popupMenu = (JPopupMenu) menuItem.getParent();
				Component invoker = popupMenu.getInvoker();
				JComponent invokerAsJComponent = (JComponent) invoker;
				Container topLevel = invokerAsJComponent.getTopLevelAncestor();
				handleContextMenuAction((Frame)topLevel, messages);
			}
		});
		return Collections.singletonList(i);
	}

	public void handleContextMenuAction(final Frame owner, IHttpRequestResponse[] messages) {
		try {
			final File gitDir = pickGitDir(owner);
			if (gitDir == null) return;
			final JDialog dlg = new JDialog(owner, NAME, false);
			final JProgressBar pb = new JProgressBar();
			final JTextArea ta = new JTextArea(25, 80);
			dlg.add(pb, BorderLayout.PAGE_START);
			dlg.add(new JScrollPane(ta), BorderLayout.CENTER);
			JRootPane rp = dlg.getRootPane();
			rp.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			dlg.pack();
			dlg.setLocationRelativeTo(owner);
			dlg.setVisible(true);

			new Thread(new Runnable() {
				public void run() {
					try {
						long start = System.currentTimeMillis();
						List<ObjectId> conditions = messagesToConditions(messages);
						Set<RevCommit> cs = findCommits(gitDir, conditions, new CommitFeedback() {
							public void setCommitCount(final int count) {
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										pb.setMaximum(count);
									}
								});
							}

							public void startedNewHash(final ObjectId hash) {
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										ta.append("started working on " + hash + "\n");
									}
								});
							}

							public void setCommitProgress(final int progress) {
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										pb.setValue(progress);
									}
								});
							}

							public void blobNotInRepository(final ObjectId hash) {
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										ta.append("blob not in repository: " + hash + "\n");
									}
								});
							}
						});
						long delta = System.currentTimeMillis() - start;
						ByteArrayOutputStream baos = new ByteArrayOutputStream();
						try (PrintStream ps = new PrintStream(baos, false, "UTF-8")) {
							ps.format("Processing took %d ms.\n", delta);
							reportCommits(cs, ps);
						}
						String msg = new String(baos.toByteArray(), StandardCharsets.UTF_8);
						SwingUtilities.invokeLater(new Runnable() {
							public void run() {
								ta.append(msg);
							}
						});
					} catch (Exception e) {
						SwingUtilities.invokeLater(new Runnable() {
							public void run() {
								reportError(e, "Git version error"); // FIXME
							}
						});
					}
				}
			}).start();
		} catch (Exception e) {
			reportError(e, "Git version error"); // FIXME
		}
	}

	private File pickGitDir(Frame owner) {
		JFileChooser chooser = new JFileChooser();
		if (lastGitDir != null) chooser.setCurrentDirectory(lastGitDir);
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setAcceptAllFileFilterUsed(false);
		chooser.setFileHidingEnabled(false); // .git is considered hidden
		chooser.setDialogTitle("Select the Git repository (foo.git or foo/.git)");
		if (chooser.showOpenDialog(owner) != JFileChooser.APPROVE_OPTION) return null;
		File gitDir = chooser.getCurrentDirectory();
		File gitSubDir = new File(gitDir, ".git");
		if (gitSubDir.exists()) gitDir = gitSubDir;
		lastGitDir = gitDir;
		return gitDir;
	}

	private List<ObjectId> messagesToConditions(IHttpRequestResponse[] messages) throws NoSuchAlgorithmException {
		List<ObjectId> conditions = new ArrayList<>(messages.length);
		MessageDigest md = MessageDigest.getInstance("SHA");
		for (IHttpRequestResponse messageInfo : messages) {
			IHttpService hs = messageInfo.getHttpService();
			IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
			IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
			byte[] response = messageInfo.getResponse();
			int offset = respInfo.getBodyOffset();
			int length = response.length - offset;
			md.reset();
			String prefix = String.format("blob %d\0", length);
			md.update(prefix.getBytes(StandardCharsets.US_ASCII));
			md.update(response, offset, length);
			conditions.add(ObjectId.fromRaw(md.digest()));
		}
		return conditions;
	}

	public static void main(String[] args) throws Exception {
		File gitDir = new File(args[0]);

		Iterable<ObjectId> conditions = Arrays.asList(args).subList(1,
				args.length).stream().map(h -> ObjectId.fromString(h)).collect(Collectors.toList());
		Set<RevCommit> cs = findCommits(gitDir, conditions, new CommitFeedback() {
			int count = 0;
			char[] chars = new char[100];

			public void setCommitCount(int count) {
				this.count = count;
			}

			public void startedNewHash(ObjectId hash) {
				System.err.println("\nstarted working on " + hash);
			}

			public void setCommitProgress(int progress) {
				int percent = progress * 100 / count;
				for (int i = 0; i < 100; i++) {
					chars[i] = i <= percent ? '#' : ' ';
				}
				System.err.print(String.format("\r[%s] %3d%%", new String(chars), percent));
			}

			public void blobNotInRepository(ObjectId hash) {
				System.err.format("\nBlob not in repository: %s\n", hash);
			}
		});
		System.err.println();
		reportCommits(cs, System.out);
	}

	private static void reportCommits(Set<RevCommit> cs, PrintStream ps) {
		if (cs == null || cs.isEmpty()) {
			ps.println("No commits matched the observed file contents.");
			return;
		}
		ps.format("The specified files are present in %d commits.\n\n", cs.size());
		List<RevCommit> cl = new ArrayList<>(cs);
		Collections.sort(cl, new Comparator<RevCommit>() {
			public int compare(RevCommit c1, RevCommit c2) {
				return c1.getCommitTime() - c2.getCommitTime();
			}
		});
		reportCommit(ps, "first", cl.get(0));
		reportCommit(ps, "last", cl.get(cl.size() - 1));
		if (cl.size() < 64) {
			ps.format("\nThe full list of affected commits is below:\n\n%s", cl);
		}
	}

	private static void reportCommit(PrintStream ps, String which, RevCommit commit) {
		ps.format("The %s commit that matches the observed file contents is ", which);
		ps.print(commit.abbreviate(10));
		ps.format(" which was committed at %s\n",
				new java.util.Date(commit.getCommitTime() * 1000L));
	}

	private void reportError(Throwable t, String title) {
		if (title != null) JOptionPane.showMessageDialog(null, t.getMessage(),
				title, JOptionPane.ERROR_MESSAGE);
		t.printStackTrace(new PrintStream(stderr));
	}

	private interface CommitFeedback {
		public void startedNewHash(ObjectId hash);
		public void setCommitCount(int count);
		public void setCommitProgress(int progress);
		public void blobNotInRepository(ObjectId hash);
	}

	private static Set<RevCommit> findCommits(File gitDir,
			Iterable<ObjectId> conditions, CommitFeedback fb) throws IOException, GitAPIException {
		Set<RevCommit> commonCommits = null;
		try (Repository repository = new FileRepositoryBuilder().setGitDir(gitDir).build()) {
			try (Git git = new Git(repository)) {
				int count = 0;
				for (RevCommit commit : git.log().all().call()) count++;
				fb.setCommitCount(count);
				Iterable<RevCommit> commits = git.log().all().call();
				for (ObjectId hash : conditions) {
					if (!repository.hasObject(hash)) {
						fb.blobNotInRepository(hash);
						continue;
					}

					Set<RevCommit> matchingCommits = new HashSet<>();
					Set<AnyObjectId> knownToContain = new HashSet<>();
					Set<AnyObjectId> knownToBeFreeOf = new HashSet<>();

					fb.startedNewHash(hash);
					if (commonCommits != null) fb.setCommitCount(commonCommits.size());

					int i = 0;
					for (RevCommit commit : commits) {
						if (i++ % 64 == 0) fb.setCommitProgress(i);
						RevTree tree = commit.getTree();
						try (TreeWalk treeWalk = new TreeWalk(repository)) {
							treeWalk.addTree(tree);
							if (isHashInTree(treeWalk, tree, hash, knownToContain, knownToBeFreeOf)) {
								commit.disposeBody();
								matchingCommits.add(commit);
							}
						}
					}
					fb.setCommitProgress(i);

					if (matchingCommits.isEmpty()) {
						fb.blobNotInRepository(hash);
						continue;
					} else {
						commonCommits = matchingCommits;
						commits = commonCommits;
					}
					if (commonCommits.size() < 2) break; // TODO conflicting conditions?
				}
			}
		}
		return commonCommits;
	}

	private static boolean isHashInTree(TreeWalk treeWalk, AnyObjectId tree,
			ObjectId hash, Set<AnyObjectId> knownToContain,
			Set<AnyObjectId> knownToBeFreeOf) throws IOException {
		MutableObjectId mid = new MutableObjectId();
		List<AnyObjectId> stack = new ArrayList<>();
		stack.add(tree);
		while (treeWalk.next()) {
			int stackTop = stack.size() - 1;
			if (stackTop != treeWalk.getDepth()) knownToBeFreeOf.add(stack.remove(stackTop));
			treeWalk.getObjectId(mid, 0);
			if (mid.equals(hash)) {
				knownToContain.addAll(stack);
				return true;
			}
			if (treeWalk.isSubtree()) {
				if (knownToBeFreeOf.contains(mid)) continue; // more likely ho happen
				if (knownToContain.contains(mid)) return true;
				treeWalk.enterSubtree();
				stack.add(mid.toObjectId());
			}
		}
		knownToBeFreeOf.add(tree); // because of EOF, it won't be mutated in caller
		return false;
	}
}
