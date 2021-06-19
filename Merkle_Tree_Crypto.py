from hashlib import sha256
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64


# for inputs 1-7
class Node:
    """
    a class to represent a node in the merkle tree
    """

    def __init__(self, data):
        self.data = data
        self.hashed_data = sha256(data.encode()).hexdigest()
        self.left_child = None
        self.right_child = None
        self.parent = None


def create_leaves_nodes(leaves_list):
    """
    the function creates a list of leaves of Node object
    """
    nodes = []
    for leaf in leaves_list:
        nodes.append(Node(leaf))
    return nodes


def create_parent_node(first_node, second_node):
    """
    the function receives 2 siblings and returns their parent
    """
    parent_node = Node(first_node.hashed_data + second_node.hashed_data)
    parent_node.left_child = first_node
    parent_node.right_child = second_node
    return parent_node


# input 2
def create_merkle_tree(leaves_nodes):
    """
    the function create a merkle tree and returns the root
    """
    # while loop to iterate over the layers of the merkle tree- in the end of
    # this loop we receive the root
    while len(leaves_nodes) > 1:
        layer_above = []
        # for loop to build one layer above
        for i in range(0, len(leaves_nodes), 2):
            first_node = leaves_nodes[i]
            # if arrived at the last node (a node that doesn't have a sibling),
            # append it and break
            if i >= len(leaves_nodes) - 1:
                layer_above.append(first_node)
                break
            second_node = leaves_nodes[i + 1]
            # create the parent node, update children and append
            parent_node = create_parent_node(first_node, second_node)
            first_node.parent = parent_node
            second_node.parent = parent_node
            layer_above.append(parent_node)
        leaves_nodes = layer_above
    return leaves_nodes[0]


# input 3
def proof_of_inclusion(index, leaves_nodes, root):
    """
    return proof of inclusion for a leaf
    """
    # if index is out of range
    if index < 0 or index > len(leaves_nodes) - 1:
        return ''
    # the leaf required
    curr_node = leaves_nodes[index]
    proof = ''
    # iterate until the root
    while root != curr_node:
        parent = curr_node.parent
        left = parent.left_child
        # build the proof - check if curr_node is right child or left child and
        # append it to the proof string
        if curr_node == left:
            proof += '1' + parent.right_child.hashed_data + ' '
        else:
            proof += '0' + left.hashed_data + ' '
        # climb one level up in the tree
        curr_node = parent
    return str(root.hashed_data + ' ' + proof)


# input 4
def check_proof_of_inclusion(leaf, root, proof):
    """
    return true if the proof is correct, otherwise false
    """
    hashed_data = sha256(leaf.encode()).hexdigest()
    index = 0
    # iterate and digest the hash of each level until finding the root
    while root != hashed_data and index < len(proof):
        curr_node = proof[index]
        if curr_node.startswith('0'):
            hashed_data = sha256(curr_node[1:].encode() +
                                 hashed_data.encode()).hexdigest()
        elif curr_node.startswith('1'):
            hashed_data = sha256(hashed_data.encode() +
                                 curr_node[1:].encode()).hexdigest()
        index += 1
    if root == hashed_data:
        return True
    return False


# input 5
def generate_RSA_keys():
    """
    the function generates a pair of RSA asymmetric keys (sk,pk)
    """
    # generate the secret key
    secret_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # generate the public key
    # (the public key is a derivative of the secret key)
    public_key = secret_key.public_key()
    # format it to PEM
    pem_sk = secret_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pk = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_sk, pem_pk


# helper function for input 6
def part6_input(user_input):
    """
    handle getting the params of input 6
    """
    key = ""
    while user_input != "":
        key += user_input + "\n"
        user_input = input()
    key = key[2:]
    return key


# input 6
def sign_root(private_key, root):
    """
    sign the root of the tree and return it
    """
    private_key = str.encode(private_key)
    private_key_pem = serialization.load_pem_private_key(private_key,
                                                         None)
    message = str.encode(root.hashed_data)
    signature = private_key_pem.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    root_signature = base64.b64encode(signature).decode()
    return root_signature


# helper function for input 7
def part7_input(user_input):
    """
    handle getting the params of input 7
    """
    public_key = ""
    while user_input != "":
        public_key += user_input + "\n"
        user_input = input()
    public_key = public_key[2:]

    user_input = input()
    user_input = user_input.split(' ')
    signature = user_input[0]
    value = user_input[1]

    return public_key, signature, value


# input 7
def verify_signature(public_key, signature, value):
    """
    verify the correctness of a signature
    """
    public_key = str.encode(public_key)
    public_key_pem = serialization.load_pem_public_key(public_key,
                                                       backend=default_backend())
    signature = str.encode(signature)
    signature = base64.decodebytes(signature)

    value = str.encode(value)

    try:
        public_key_pem.verify(
            signature,
            value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("True")
    except InvalidSignature:
        print("False")


# class used for input 8-11

class SparseMerkleTree:
    """
    A class representing the sparse merkle tree
    """

    def calculate_parent_hash(self, first, second):
        """
        gets the value of 2 elements and returns the hash of their combination
        """
        data = first + second
        new_hash = sha256(data.encode()).hexdigest()
        return new_hash

    def __init__(self):
        self.levels = 256
        self.nodes = {}
        self.empty_sparse = [0] * 257
        self.empty_sparse[0] = '0'

        for index in range(1, self.levels + 1):
            data = self.empty_sparse[index - 1] + self.empty_sparse[index - 1]
            new_hash = sha256(data.encode()).hexdigest()
            self.empty_sparse[index] = new_hash
            self.empty_sparse[index] = self.calculate_parent_hash(self.empty_sparse[index - 1],
                                                                  self.empty_sparse[index - 1])

    def digest_converter(self, digest):
        """
        converts the digest to binary
        """
        binary = bin(int(digest, 16))[2:].zfill(len(digest * 4))
        return binary

    # helper function for input 8
    def last_is_zero(self, index):
        """
        helper function for mark_leaf function
        """
        offset = self.levels - len(index)
        node_father = index[:-1]
        node_brother = index[:-1] + '1'

        if node_brother in self.nodes:
            self.nodes[node_father] = self.calculate_parent_hash(
                self.nodes[index],
                self.nodes[node_brother])
        else:
            self.nodes[node_father] = self.calculate_parent_hash(
                self.nodes[index],
                self.empty_sparse[offset])

    # helper function for input 8
    def last_is_one(self, index):
        """
        helper function for mark_leaf function
        """
        offset = self.levels - len(index)
        node_father = index[:-1]

        node_brother = index[-1] + '0'

        if node_brother in self.nodes:
            self.nodes[node_father] = self.calculate_parent_hash(
                self.nodes[node_brother],
                self.nodes[index])
        else:
            self.nodes[node_father] = self.calculate_parent_hash(
                self.empty_sparse[offset],
                self.nodes[index])

    # input 8
    def mark_leaf(self, digest):
        """
        given a digest, travels the sparse merkle tree and marks the
        appropriate leaf
        """
        index = self.digest_converter(digest)
        index_len = len(index)
        self.nodes[index] = '1'

        while index_len > 0:
            if index[-1] == '1':
                self.last_is_one(index)
            else:
                self.last_is_zero(index)
            index = index[:-1]
            index_len = len(index)

    # input 9
    def get_root(self):
        """
        returns the root of the sparse merkle tree
        """
        if len(self.nodes) == 0:
            root = self.empty_sparse[self.levels]
            return root
        else:
            root = self.nodes['']
            return root

    # input 10
    def smt_proof_of_inclusion(self, digest):
        """
        Create a proof using the input digest
        """
        proof = [self.get_root()]
        digest_binary = self.digest_converter(digest)
        not_in_nodes = False

        # using the binary digest to build the proof
        end_loop = False
        while len(digest_binary) > 0 and not end_loop:
            if digest_binary[-1] == '1':
                node_brother = digest_binary[:-1] + '0'
            else:
                node_brother = digest_binary[:-1] + '1'

            # if both not in nodes set the flag to true
            if node_brother not in self.nodes and \
                    digest_binary not in self.nodes:
                not_in_nodes = True
                digest_binary = digest_binary[:-1]  # trimming the digest
            else:
                if not_in_nodes is True:
                    offset = self.levels - len(digest_binary)
                    proof.append(self.empty_sparse[offset])
                end_loop = True

        # if the digest is finished then we can add the root to the proof
        if len(digest_binary) == 0:
            proof.append(self.get_root())

        if len(digest_binary) == self.levels and \
                digest_binary not in self.nodes:
            self.nodes[digest_binary] = '0'

        while len(digest_binary) > 0:
            # using the binary digest to build the proof
            offset = self.levels - len(digest_binary)

            last = digest_binary[-1]
            if last == '1':
                node_brother = digest_binary[:-1] + '0'
            else:
                node_brother = digest_binary[:-1] + '1'

            if node_brother in self.nodes:
                proof.append(self.nodes[node_brother])
            else:
                add_to_proof = str(self.empty_sparse[offset])
                proof.append(add_to_proof)

            digest_binary = digest_binary[:-1]  # trimming the digest
        return proof

    # helper function for input 11
    def check_more_then_levels(self, length_proof_to_verify):
        """
        if the proof is bigger then 256 it isn't legal
        """
        if length_proof_to_verify > self.levels:
            return "False"

    # helper function for input 11
    def check_less_then_levels(self, proof_to_verify, length_proof_to_verify,
                               classification, digest_binary, root_to_verify):
        """
        checks the proof for the case that it is less the 256
        """
        # if the proof is less then 256 levels then we know that the
        # classification must not be 1
        if classification == '1':
            return "False"
        cut_location = self.levels - length_proof_to_verify + 1
        default_nodes = self.empty_sparse[cut_location]
        if proof_to_verify[0] != default_nodes:
            return "False"

        # calculating where we need to cut the tree and cutting it
        tree_cut = -(self.levels - length_proof_to_verify + 1)
        digest_binary = digest_binary[:tree_cut]

        true_root = proof_to_verify[0]
        proof_to_verify = proof_to_verify[1:]

        index = 0
        digest_binary_length = len(digest_binary)
        while digest_binary_length > 0:
            # building the proof according to the digest
            last = digest_binary[-1]
            if last == '0':
                true_root = self.calculate_parent_hash(true_root,
                                                       proof_to_verify[index])
            if last == '1':
                true_root = self.calculate_parent_hash(proof_to_verify[index],
                                                       true_root)
            digest_binary = digest_binary[:-1]  # trimming the digest
            digest_binary_length = len(digest_binary)
            index += 1

        # compare the root and return if they match
        if true_root != root_to_verify:
            return "False"
        else:
            return "True"

    # helper function for input 11
    def check_equals_levels(self, proof_to_verify, length_proof_to_verify,
                            digest_binary, root_to_verify, classification):
        """
        if the proof is exactly 256 levels we calculate the root and check if
        it equals to the one in the proof we are verifying
        """
        true_root = classification
        for index in range(length_proof_to_verify):
            last = digest_binary[-1]
            if last == '0':
                true_root = self.calculate_parent_hash(true_root,
                                                       proof_to_verify[index])
            if last == '1':
                true_root = self.calculate_parent_hash(proof_to_verify[index],
                                                       true_root)
            digest_binary = digest_binary[:-1]  # trimming the digest

        # compare the root and return if they match
        if true_root != root_to_verify:
            return "False"
        return "True"

    # input 11
    def smt_check_proof_of_inclusion(self, digest_binary, classification,
                                     root_to_verify, proof_to_verify):
        """
        Return true if the proof is correct, otherwise false.
        We divide top several cases - if the proof is smaller, larger or equals
        to 256 and check accordingly
        """
        length_proof_to_verify = len(proof_to_verify)
        # proof starts from the classification

        # if the proof is bigger then 256 it isn't legal
        if self.check_more_then_levels(length_proof_to_verify) == "False":
            return "False"

        if length_proof_to_verify < self.levels:
            return self.check_less_then_levels(proof_to_verify,
                                               length_proof_to_verify,
                                               classification, digest_binary,
                                               root_to_verify)

        # if the proof is exactly 256 levels we calculate the root and check if
        # it equals to the one in the proof we are verifying
        if length_proof_to_verify == self.levels:
            return self.check_equals_levels(proof_to_verify,
                                            length_proof_to_verify,
                                            digest_binary, root_to_verify,
                                            classification)

    # helper function for input 11
    def part11_input(self, params):
        """
        handle getting the params of input 11
        """
        digest_binary = self.digest_converter(params[1])
        classification = params[2]
        root = params[3]
        proof = params[4:]

        return digest_binary, classification, root, proof


def main():
    # create the merkle tree
    root = None
    # create the sparse merkle tree
    smt = SparseMerkleTree()
    # list of leaves as strings (raw input from user)
    leaves_list = []
    # list of leaves as Node objects
    leaves_nodes = []

    while True:
        user_input = input()
        params = user_input.split(' ')
        try:
            if params[0] == '1':
                leaves_list.append(params[1])
                leaves_nodes = create_leaves_nodes(leaves_list)
                root = create_merkle_tree(leaves_nodes)
            elif params[0] == '2':
                if root is not None:
                    print(root.hashed_data)
                else:
                    print("")
            elif params[0] == '3':
                if root is not None:
                    proof = proof_of_inclusion(int(params[1]), leaves_nodes,
                                               root)
                    print(proof)
                else:
                    print("")
            elif params[0] == '4':
                if root is not None:
                    print(
                        check_proof_of_inclusion(params[1], params[2],
                                                 params[3:]))
                else:
                    print("")
            elif params[0] == '5':
                secret_key, public_key = generate_RSA_keys()
                print(secret_key.decode("utf-8"))
                print(public_key.decode("utf-8"))
            elif params[0] == '6':
                if root is not None:
                    key = part6_input(user_input)
                    root_signature = sign_root(key, root)
                    print(root_signature)
                else:
                    print("")
            elif params[0] == '7':
                public_key, signature, value = part7_input(user_input)
                verify_signature(public_key, signature, value)
            elif params[0] == '8':
                digest = params[1]
                smt.mark_leaf(digest)
            elif params[0] == '9':
                proof = smt.get_root()
                print(proof)
            elif params[0] == '10':
                digest = params[1]
                proof = smt.smt_proof_of_inclusion(digest)
                proof = ' '.join(proof)
                print(proof)
            elif params[0] == '11':
                digest, classification, root, proof = smt.part11_input(params)
                print(smt.smt_check_proof_of_inclusion(digest, classification,
                                                       root, proof))
            else:
                print("")
        except:
            print("")


if __name__ == '__main__':
    main()
