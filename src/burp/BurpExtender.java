package burp;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.stream.*;

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
				handleContextMenuAction(messages);
			}
		});
		return Collections.singletonList(i);
	}

	public void handleContextMenuAction(IHttpRequestResponse[] messages) {
		try {
			JFileChooser chooser = new JFileChooser();
			chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			chooser.setAcceptAllFileFilterUsed(false);
			chooser.setFileHidingEnabled(false); // .git is considered hidden
			if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
			File gitDir = chooser.getCurrentDirectory();
			File gitSubDir = new File(gitDir, ".git");
			if (gitSubDir.exists()) gitDir = gitSubDir;
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
			long start = System.currentTimeMillis();
			Set<RevCommit> cs = findCommits(gitDir, conditions, null); // TODO implement UI feedback
			long delta = System.currentTimeMillis() - start;
			try (PrintStream ps = new PrintStream(stderr)) {
				ps.format("Processing took %d ms.\n", delta);
				reportCommits(cs, ps);
			}
		} catch (Exception e) {
			reportError(e, "Git version error"); // FIXME
		}
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
		ps.format("\nThe full list of affected commits is below:\n\n%s", cl);
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
	}

	private static Set<RevCommit> findCommits(File gitDir,
			Iterable<ObjectId> conditions, CommitFeedback fb) throws IOException, GitAPIException {
		Set<RevCommit> commonCommits = null;
		try (Repository repository = new FileRepositoryBuilder().setGitDir(gitDir).build()) {
			try (Git git = new Git(repository)) {
				int count = 0;
				for (RevCommit commit : git.log().all().call()) count++;
				fb.setCommitCount(count);
				for (ObjectId hash : conditions) {
					// TODO does the repository even contain the blob?
					//  - sanity check before going through commits/trees
					//  - would produce empty matchingCommits (see below)
					//  - skip hash / return with null (short circuit)?
					Set<RevCommit> matchingCommits = new HashSet<>();
					Set<AnyObjectId> knownToContain = new HashSet<>();
					Set<AnyObjectId> knownToBeFreeOf = new HashSet<>();

					fb.startedNewHash(hash);

					int i = 0;
					for (RevCommit commit : git.log().all().call()) {
						if (i++ % 64 == 0) fb.setCommitProgress(i);
						RevTree tree = commit.getTree();
						try (TreeWalk treeWalk = new TreeWalk(repository)) {
							treeWalk.addTree(tree);
							if (isHashInTree(treeWalk, tree, hash, knownToContain, knownToBeFreeOf) == RecursiveResult.FOUND) {
								commit.disposeBody();
								matchingCommits.add(commit);
							}
						}
					}

					if (commonCommits == null) {
						commonCommits = matchingCommits;
					} else {
						commonCommits.retainAll(matchingCommits);
						// TODO what if matchingCommits is empty?
						//  - return immediately / short circuit?
						//  - ignore file (see conflict below as well)
					}
					if (commonCommits.size() < 2) break; // TODO conflicting conditions?
				}
			}
		}
		return commonCommits;
	}

	private enum RecursiveResult { FOUND, NOT_FOUND, EOF; };

	private static RecursiveResult isHashInTree(TreeWalk treeWalk, AnyObjectId tree,
			ObjectId hash, Set<AnyObjectId> knownToContain,
			Set<AnyObjectId> knownToBeFreeOf) throws IOException {
		int depth = treeWalk.getDepth();
		MutableObjectId mid = new MutableObjectId();
		boolean skip = false;
treewalk_loop:
		while (skip || treeWalk.next()) {
			skip = false;
			if (treeWalk.getDepth() != depth) {
				knownToBeFreeOf.add(tree.toObjectId());
				return RecursiveResult.NOT_FOUND;
			}
			treeWalk.getObjectId(mid, 0);
			if (mid.equals(hash)) {
				knownToContain.add(tree.toObjectId());
				return RecursiveResult.FOUND;
			}
			if (treeWalk.isSubtree()) {
				if (knownToBeFreeOf.contains(mid)) continue; // more likely ho happen
				if (knownToContain.contains(mid)) return RecursiveResult.FOUND;
				treeWalk.enterSubtree();
				RecursiveResult rr = isHashInTree(treeWalk, mid, hash, knownToContain, knownToBeFreeOf);
				switch (rr) {
					case FOUND:
						knownToContain.add(tree.toObjectId());
						return RecursiveResult.FOUND;
					case EOF:
						break treewalk_loop;
					case NOT_FOUND:
						skip = true;
				}
			}
		}
		knownToBeFreeOf.add(tree); // because of EOF, it won't be mutated in caller
		return RecursiveResult.EOF;
	}
}
